from sqlalchemy import INT, JSON, AsyncAdaptedQueuePool, BigInteger, DateTime, ForeignKey, String, delete, func, or_, and_, select, true, update, case
from sqlalchemy.orm import DeclarativeBase, Mapped, joinedload, load_only, mapped_column, relationship, selectinload
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from datetime import datetime
from enum import IntEnum
from typing import Any, Optional, List, Protocol, Sequence, runtime_checkable, cast
from uuid import UUID, uuid4
import discord
import logging
import asyncio
import time

logger = logging.getLogger(__name__)

def frmt(amount: int) -> str:
	"""
	Formats balance in cents into `xx.yy` format.
	
	:param amount: The amount in cents.
	
	:returns: Balance in `xx.yy` format.
	"""
	return f"{amount // 100}.{amount % 100:02}"

class Base(DeclarativeBase):
	type_annotation_map = {
		dict[str, Any]: JSON
	}

# ========== IntEnums ==========

class LogLevels(IntEnum):
	"""Enum used to represent the differnet possible log record levels"""
	Private = 51
	Public = 52

class AccountType(IntEnum):
	"""Enum used to represent the different possible account types."""
	USER = 0
	GOVERNMENT = 1
	CORPORATION = 2
	CHARITY = 3
	FINANCIAL = 4

class Permissions(IntEnum):
	"""
	Enum used to represent the different permissions.
	
	Permissions are ranked in the following order from top to bottom:

	1. Permissions assigned to the user globally (in all economies)
	2. Permissions assigned to the user for a specific economy
	3. Permissions assigned to the user directly
	4. Permissions assigned to the user through a role
	"""

	# User
	OPEN_ACCOUNT = 0
	VIEW_BALANCE = 1
	CLOSE_ACCOUNT = 2
	TRANSFER_FUNDS = 3
	CREATE_RECURRING_TRANSFERS = 4

	# Guild administrator
	MANAGE_FUNDS = 5
	MANAGE_TAX_BRACKETS = 6

	# Developer
	MANAGE_PERMISSIONS = 7
	MANAGE_ECONOMIES = 8

	# Moderator
	OPEN_SPECIAL_ACCOUNT = 9
	LOGIN_AS_ACCOUNT = 10

	# Attributes
	GOVERNMENT_OFFICIAL = 11
	USES_EPHEMERAL = 12

class TaxType(IntEnum):
	"""Enum used to represent the different types of taxation methods."""
	WEALTH_MARGINAL = 0
	INCOME = 1
	VAT = 2
	WEALTH_FLAT = 3

class TransactionType(IntEnum):
	"""Enum used to represent the different types of transactions."""
	PERSONAL = 0
	INCOME = 1
	PURCHASE = 2

class Actions(IntEnum):
	"""Enum used to represent the different potential actions."""
	TRANSFER = 0
	MANAGE_FUNDS = 1
	UPDATE_PERMISSIONS = 2
	UPDATE_TAX_BRACKETS = 3
	UPDATE_ECONOMIES = 4
	PERFORM_TAXES = 5
	UPDATE_ACCOUNTS = 6

class CUD(IntEnum):
	"""Enum used to represent the type of action taken."""
	CREATE = 0
	UPDATE = 1
	DELETE = 2

class KeyType(IntEnum):
	"""Enum used to represent the different types of API key."""
	GRANT = 0
	MASTER = 1

# ========= Models ==========

class Economy(Base):
	"""A class used to represent an economy stored in the database."""
	__tablename__ = "economies"

	economy_id: Mapped[UUID] = mapped_column(primary_key=True)
	owner_guild_id: Mapped[int] = mapped_column(BigInteger(), nullable=False, unique=True)
	currency_name: Mapped[str] = mapped_column(String(32), unique=True)
	currency_unit: Mapped[str] = mapped_column(String(32))

	guilds: Mapped[List["Guild"]] = relationship(back_populates="economy", cascade="delete-orphan", passive_deletes=True)
	accounts: Mapped[List["Account"]] = relationship(back_populates="economy")
	applications: Mapped[List["Application"]] = relationship(back_populates="economy")

class Guild(Base):
	"""A class used to represent a guild's economy stored in the database."""
	__tablename__ = "guilds"

	# Ticking time bomb, in roughly fifteen years this"ll break if this is still around then I wish the dev all the best. 
	# (doing something like this first should fix it tho: id = id if id < 2^63 else -(id&(2^63-1))
	# It's not ideal but unless SQL now supports unsigned types it's the best your gonna get.
	guild_id: Mapped[int] = mapped_column(BigInteger(), primary_key=True)
	
	economy_id = mapped_column(ForeignKey("economies.economy_id"))
	economy: Mapped[Economy] = relationship(back_populates="guilds")

class Application(Base):
	"""A class used to represent an API application stored in the database."""
	__tablename__ = "applications"

	application_id: Mapped[UUID] = mapped_column(primary_key=True)
	application_name: Mapped[str] = mapped_column(String(64))
	owner_id: Mapped[int] = mapped_column(BigInteger())

	economy_id = mapped_column(ForeignKey("economies.economy_id"))
	api_keys: Mapped[List["APIKey"]] = relationship(back_populates="application")
	economy: Mapped[Economy] = relationship(back_populates="applications")

class APIKey(Base):
	"""A class used to represent an API key stored in the database."""
	__tablename__ = "api_keys"

	# Using an integer datatype to ensure that the ID will not clash with any Discord snowflakes (any Discord ID created after 2015-1-1-0:0:1.024 should not clash)
	# Ref: https://discord.com/developers/docs/reference#snowflakes
	key_id: Mapped[int] = mapped_column(INT(), primary_key=True, autoincrement=True) 
	application_id = mapped_column(ForeignKey("applications.application_id", ondelete="CASCADE"))
	internal_app_id: Mapped[UUID] = mapped_column(nullable=True)
	issuer_id: Mapped[int] = mapped_column(BigInteger(), nullable=False)

	spending_limit: Mapped[int] = mapped_column(nullable=True)
	spent_to_date: Mapped[int] = mapped_column(nullable=True, default=0)

	type: Mapped[KeyType] = mapped_column(default=KeyType.GRANT)
	enabled: Mapped[bool] = mapped_column(default=False)
	application: Mapped[Application] = relationship(back_populates="api_keys")

	def activate(self):
		"""
		Activates the API key.
		"""
		self.enabled = True

class Account(Base):
	"""A class used to represent an account stored in the database."""
	__tablename__ = "accounts"

	account_id: Mapped[UUID] = mapped_column(primary_key=True)
	account_name: Mapped[str] = mapped_column(String(64))
	owner_id: Mapped[Optional[int]] = mapped_column(BigInteger(), nullable=True)

	account_type: Mapped[AccountType] = mapped_column()
	balance: Mapped[int] = mapped_column(default=0)
	income_to_date: Mapped[int] = mapped_column(default=0)
	economy_id = mapped_column(ForeignKey("economies.economy_id"))
	deleted: Mapped[bool] = mapped_column(default=False)
	
	economy: Mapped[Economy] = relationship(back_populates="accounts")
	update_notifiers: Mapped[List["BalanceUpdateNotifier"]] = relationship(back_populates="account")

	def get_update_notifiers(self) -> List[int]:
		"""
		Returns the update notifiers of the account.
		
		:returns: A list of the user IDs of the update notifiers of the account.
		"""
		return [i.owner_id for i in self.update_notifiers] + ([self.owner_id,] if self.owner_id else [])

	def get_balance(self) -> str:
		"""
		Returns the balance formatted as a string.

		This method should be used to avoid any weird floating point shenanigans when calculating the balance.
		
		:returns: The balance formatted as a string.
		"""
		return frmt(self.balance)

	def get_name(self) -> str:
		"""
		Returns the name of the account.
		
		:returns: The name of the account.
		"""
		if self.account_type == AccountType.USER:
			return f"<@{self.owner_id}>"
		return self.account_name

	def delete(self):
		"""
		Marks the account as deleted.
		"""
		self.deleted = True

class Transaction(Base):
	"""A class used to represent transactions stored in the database."""
	__tablename__ = "transactions"

	transaction_id: Mapped[int] = mapped_column(primary_key=True)
	actor_id: Mapped[int] = mapped_column(BigInteger(), nullable=False)

	timestamp: Mapped[datetime] = mapped_column(DateTime(), nullable=False, default=datetime.now)
	action: Mapped[Actions] = mapped_column()

	# Denotes the type of action taking place; can be either CREATE, UPDATE or DELETE
	cud: Mapped[CUD] = mapped_column() 
	economy_id: Mapped[UUID] = mapped_column(nullable=True)

	# Transfers will use target_account as the source account for the transaction
	target_account_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.account_id"), nullable=True) 
	destination_account_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.account_id"), nullable=True)
	amount: Mapped[int] = mapped_column(nullable=True)

	# TODO: Let Stoner document this. 
	meta: Mapped[dict[str, Any]] = mapped_column(default={}) 

	destination_account: Mapped[Account] = relationship(foreign_keys=[destination_account_id])
	target_account: Mapped[Account] = relationship(foreign_keys=[target_account_id])

class BalanceUpdateNotifier(Base):
	"""A class used to represent an account's balance update notifier stored in the database."""
	__tablename__ = "balance_update_notifiers"
	notifier_id: Mapped[UUID] = mapped_column(primary_key=True)
	owner_id: Mapped[int] = mapped_column(BigInteger(), nullable=False)
	account_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.account_id", ondelete="CASCADE"))
	account: Mapped[Account] = relationship(back_populates="update_notifiers")

class Permission(Base):
	"""A class used to represent a permission as stored in the database."""
	__tablename__ = "perms"

	entry_id: Mapped[UUID] = mapped_column(primary_key=True)
	account_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.account_id"), nullable=True)

	# Can also be a role ID or an API key ID < 4194304, due to how Discord works there are zero chances of a collision.
	user_id: Mapped[int] = mapped_column(BigInteger(), index=True) 
	permission: Mapped[Permissions] = mapped_column()
	allowed: Mapped[bool] = mapped_column()
	economy_id: Mapped[UUID] = mapped_column(
		ForeignKey("economies.economy_id", ondelete="CASCADE"), 
		nullable=True, 
		index=True 
	)

class Tax(Base):
	"""A class used to represent a tax bracket stored in the database."""
	__tablename__ = "taxes"

	entry_id: Mapped[UUID] = mapped_column(primary_key=True)
	tax_name: Mapped[str] = mapped_column(String(32))

	affected_type: Mapped[AccountType] = mapped_column()
	tax_type: Mapped[TaxType] = mapped_column()

	bracket_start: Mapped[int] = mapped_column()
	bracket_end: Mapped[Optional[int]] = mapped_column(nullable=True)
	rate: Mapped[int] = mapped_column()

	to_account_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.account_id"))
	economy_id: Mapped[UUID] = mapped_column(ForeignKey("economies.economy_id"))

	to_account: Mapped[Account] = relationship()
	economy: Mapped[Economy] = relationship()

class RecurringTransfer(Base):
	"""A class used to represent a recurring transfer as stored in the database."""
	__tablename__ = "recurring_transfers"
	
	entry_id: Mapped[UUID] = mapped_column(primary_key=True)
	authorisor_id: Mapped[int] = mapped_column(BigInteger())

	from_account_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.account_id"))
	from_account: Mapped[Account] = relationship(foreign_keys=from_account_id)

	to_account_id: Mapped[UUID] = mapped_column(ForeignKey("accounts.account_id"))
	to_account: Mapped[Account] = relationship(foreign_keys=to_account_id)

	amount: Mapped[int] = mapped_column()
	last_payment_timestamp: Mapped[float] = mapped_column()
	payment_interval: Mapped[int] = mapped_column() # IN SECONDS

	# Thanks hackerman :)
	number_of_payments_left: Mapped[Optional[int]] = mapped_column(nullable=True) 

	transaction_type: Mapped[TransactionType] = mapped_column()

# ========== Utils ==========

class BackendException(Exception):
	"""The base exception for all backend errors."""
	pass

class UnauthorizedException(BackendException):
	"""The backend exception raised when an actor is unauthorized to perform an action (does not have the permissions to perform said action)."""
	pass

class NotFoundException(BackendException):
	"""The backend exception raised when an object is not found in the database."""
	pass

class AlreadyExistsException(BackendException):
	"""The backend exception raised when an object in the database already has a similar field value."""
	pass

class ValueError(BackendException, ValueError):
	"""The backend exception raised when an object's field has an incorrect or insufficient value."""
	pass

class HasID(Protocol):
	"""A protocol to define all objects with an ID field (users, stub users, roles, stub roles, members, etc.)."""
	id: int

@runtime_checkable
class HasRoles(Protocol):
	"""A protocol to define all member objects with a roles field (stub members and discord members)."""
	id: int
	roles: List[HasID]

type User = HasID | HasRoles

_get_roles = lambda u: [r.id for r in cast(HasRoles, u).roles] if isinstance(u, (HasRoles, discord.Member)) else []

class StubUser:
	"""
	A class to be used if a user could not be found anymore.
	This could be if the user or guild were deleted.
	"""
	
	def __init__(self, user_id: int):
		"""
		:param user_id: The user's ID.
		"""
		self.id = user_id
		self.mention = f"<@{user_id}>"
		self.roles = []

type Serialized = str | list[str | Serialized] | dict[str, str]
def make_serializable(arg: Any) -> Serialized:
	"""
	Turns objects into serializable versions of themselves through string representations where necessary.
	
	:param arg: The object to make serializable.
	
	:returns: The serialized object.
	"""
	if isinstance(arg, UUID):
		return str(arg)
	elif isinstance(arg, IntEnum):
		return arg.name
	elif isinstance(arg, (tuple, list)):
		return [make_serializable(i) for i in arg]
	elif isinstance(arg, dict):
		new_dict = {}
		for k in arg.keys():
			new_dict[k] = make_serializable(arg[k])
		return new_dict
	else:
		return arg

DAY_TO_SECOND = 86_400 # 24 hours * 60 minutes * 60 seconds

# ======== Constants ========

# a user id for the console - if I ever decide to strap a CLI onto this thing that will be its user id, 0 is an impossible discord id to have so it works for our purposes  
CONSOLE_USER_ID = 0 

DEFAULT_GLOBAL_PERMISSIONS = [
	Permissions.OPEN_ACCOUNT
]

DEFAULT_OWNER_PERMISSIONS = [
	Permissions.CLOSE_ACCOUNT,
	Permissions.TRANSFER_FUNDS,
	Permissions.CREATE_RECURRING_TRANSFERS,
	Permissions.VIEW_BALANCE,
	Permissions.LOGIN_AS_ACCOUNT
]

UNPRIVILEGED_PERMISSIONS = [
	Permissions.USES_EPHEMERAL,
	Permissions.GOVERNMENT_OFFICIAL
]

# ========= Backend =========

class Backend:
	"""An object used to call the backend database."""
	
	def __init__(self, path: str, **engine_options):
		"""
		:param path: A path or database URI to the database.
		:param engine_options: Dialect-dependent engine options.
		"""
		self.engine = create_async_engine(path, **engine_options)
		
		# apparently sessions are meant to be short-lived, oops
		self._sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

	async def initalize(self):
		"""
		Initalizes the backend by creating the necessary tables for models.

		.. note
		This function is automatically called if you use the backend as an async context manager as shown below:
		
		.. code-block:: python
		async with Backend(...) as backend:
			...
		"""
		async with self.engine.begin() as conn:
			await conn.run_sync(Base.metadata.create_all)

	async def _one_or_none(self, stmt, *, session: Optional[AsyncSession] = None):
		"""
		Returns one or None as a result of the statement.
		
		:param stmt: Statement to execute.
		:param session: (optional) Session to batch execute.
		"""
		if session:
			return (await session.execute(stmt)).scalar_one_or_none()
		else:
			async with self._sessionmaker() as session:
				return (await session.execute(stmt)).scalar_one_or_none()

	async def refresh(self, *objects):
		"""
		Refreshes detached instances of models.

		:param *objects: The objects to refresh.
		"""
		async with self._sessionmaker() as session:
			await session.flush(objects)
			for obj in objects:
				session.add(obj)
				await session.refresh(obj)

	async def tick(self):
		"""
		Triggers a tick in the server.
		Must be triggered externally.
		"""
		tick_time = time.time()
		async with self._sessionmaker.begin() as session:
			transfer_time = RecurringTransfer.last_payment_timestamp + RecurringTransfer.payment_interval

			transfers = (
				await session.execute(
					select(RecurringTransfer)
					.options(
						joinedload(RecurringTransfer.from_account).joinedload(Account.economy),
						joinedload(RecurringTransfer.to_account)
					)
					.where(transfer_time <= tick_time)
					.order_by(transfer_time.asc())
				)
			).scalars().all()

			for transfer in transfers:
				number_of_transfers = int((tick_time - transfer.last_payment_timestamp) // transfer.payment_interval)
				payments_left = transfer.number_of_payments_left
				
				for _ in range(number_of_transfers):
					if payments_left == 0:
						await session.delete(transfer)
						break

					try:
						authorisor = await self.get_member(transfer.authorisor_id, transfer.from_account.economy.owner_guild_id) or StubUser(transfer.authorisor_id)
						await self.perform_transaction(authorisor, transfer.from_account, transfer.to_account, transfer.amount, transfer.transaction_type)
						if payments_left and payments_left > 0:
							payments_left -= 1
					except Exception as e:
						logger.log(LogLevels.Private, f"Failed to perform recurring transaction of {frmt(transfer.amount)} from {transfer.from_account.account_name} to {transfer.to_account.account_name} due to: {e}")
						await self.notify_user(transfer.authorisor_id, f"Your recurring transaction of {frmt(transfer.amount)} every {transfer.payment_interval // DAY_TO_SECOND} day(s) to {transfer.to_account.account_name} was cancelled due to: {e}", "Failed Reccurring Transfer")
						await session.delete(transfer)
				else:
					transfer.number_of_payments_left = payments_left
					transfer.last_payment_timestamp = tick_time

	# === Permissions and API Applications ===

	async def get_permissions(self, user: User, economy: Optional[Economy] = None) -> Sequence[Permission]:
		"""
		Returns a member (or stub member)'s permissions.
		
		:param user: A member-like object.
		:param economy: (optional) Economy for economy-based permissions.
		
		:returns: A list of permissions.
		"""
		stmt = select(Permission) \
				.where(Permission.user_id.in_([user.id] + _get_roles(user)))
				
		if economy:
			stmt = stmt.where(Permission.economy_id == economy.economy_id)

		async with self._sessionmaker() as session:
			return (
				await session.execute(stmt)
			).scalars().all()

	async def get_authable_accounts(self, user: User, economy: Optional[Economy] = None)  -> Sequence[Account]:
		"""
		Returns all accounts a member owns or has permissions for.
		
		:param user: A member-like object.
		:param economy: (optional) Economy for economy-based permissions.
		
		:returns: A list of accounts.
		"""
		stmt = select(Account) \
			  .outerjoin(Permission) \
			  .where(
				or_(
					Permission.user_id.in_([user.id] + _get_roles(user)),
					Account.owner_id == user.id
				)
			  ) \
			  .distinct()

		if economy:
			stmt = stmt.where(Permission.economy_id == economy.economy_id).options(joinedload(Permission.economy_id))

		async with self._sessionmaker() as session:
			return (
				await session.execute(stmt)
			).scalars().all()

	async def key_has_permission(self, key: APIKey, permission: Permissions, account: Optional[Account] = None, economy: Optional[Economy] = None) -> bool:
		"""
		Checks if an API key is allowed/authorized to do something.

		:param user: A stub user object, or a Discord member object for permissions tied to roles.
		:param permission: The permission to check.
		:param account: (optional) The permission's account constraint.
		:param economy: (optional) The permission's economy constraint.
		
		:returns: Whether the user is authorized with said permission.
		"""

		actor = await self.get_member(key.issuer_id, key.application.economy.owner_guild_id) or StubUser(key.issuer_id)
		return await self.has_permission(StubUser(key.key_id), permission, account, economy) \
		   and await self.has_permission(actor, permission, account, economy)

	async def has_permission(self, user: User, permission: Permissions, account: Optional[Account] = None, economy: Optional[Economy] = None) -> bool:
		"""
		Checks if a user is allowed/authorized to do something.
		
		:param user: A stub user object, or a Discord member object for permissions tied to roles.
		:param permission: The permission to check.
		:param account: (optional) The permission's account constraint.
		:param economy: (optional) The permission's economy constraint.
		
		:returns: Whether the user is authorized with said permission.
		"""
		if user.id == CONSOLE_USER_ID:
			return True
		elif account and not economy:
			economy = await self.get_economy_by_id(account.economy_id)
		
		stmt = select(Permission) \
			  .where(
				and_(
					Permission.permission == permission,
					Permission.user_id.in_([user.id] + _get_roles(user)),
					or_(
						Permission.account_id == account.account_id if account else Permission.account_id.is_(None),
						Permission.economy_id == economy.economy_id if economy else Permission.economy_id.is_(None)
					)
				)
			  ) \
			  .distinct()

		default = False
		owner_id = account.owner_id if account is not None else None

		if permission in DEFAULT_GLOBAL_PERMISSIONS or (permission in DEFAULT_OWNER_PERMISSIONS \
														and owner_id in [user.id] + _get_roles(user)):
			default = True

		async with self._sessionmaker() as session:
			results = list((await session.execute(stmt)).scalars().all())

			if len(results) == 0:
				return default

			def _evaluate(perm: Permission):
				# Precedence for result: 
				# 1. Account & economy are null
				# 2. Account is null
				# 3. Account & economy are not null, user
				# 4. Account & economy are not null, role
				# Economy cannot be null without account being null
				if perm.account_id is None and perm.economy_id is None:
					return 1
				elif perm.account_id is None:
					return 2
				return 3 if perm.user_id == user.id else 4

			# global permissions (economy = null) > economy permissions (account = null) > user permissions > role permissions
			best = results.pop(0)
			for r in results:
				eval_r = _evaluate(r)
				eval_best = _evaluate(best)

				if eval_r < eval_best:
					best = r
				elif eval_r == eval_best and isinstance(user, discord.Member):
					r_b = user.guild.get_role(best.user_id)
					r_r = user.guild.get_role(r.user_id)
					if r_r and r_b and r_b < r_r:
						best = r
		
		return best.allowed

	async def get_application(self, app_id: UUID) -> Optional[Application]:
		"""
		Fetch an API application by its ID.
		
		:param app_id: The application ID.
		
		:returns: The application if it exists, else `None`.
		"""
		return await self._one_or_none(select(Application).where(Application.application_id == app_id).options(joinedload(Application.economy)))

	async def get_user_applications(self, user_id: int) -> Sequence[Application]:
		"""
		Fetch all applications owned by a user.
		
		:param user_id: The user ID of the user.
		
		:returns: A list of applications owned by the user.
		"""
		async with self._sessionmaker() as session:
			return (await session.execute(
				select(Application) \
				.where(Application.owner_id == user_id)
				.options(joinedload(Application.economy))
			)).scalars().all()

	async def get_application_keys(self, app_id: UUID) -> Sequence[APIKey]:
		"""
		Fetch all API keys created by an application.
		
		:param app_id: The application UUID of the application.
		
		:returns: A list of the API keys created by the application.
		"""
		async with self._sessionmaker() as session:
			return (await session.execute(
				select(APIKey) \
				.where(APIKey.application_id == app_id)
				.options(joinedload(Application.economy))
			)).scalars().all()

	async def create_application(self, actor: User, name: str, owner_id: int, economy: Economy) -> Application:
		"""
		Creates a new API application.
		
		:param actor: The actor of this action.
		:param name: The name of the application.
		:param owner_id: The user ID of the application's owner.
		:param economy: The economy in which the application is based in.
		
		:returns: The new application.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_ECONOMIES, economy=economy):
			raise UnauthorizedException(f"You do not have permission to create applications in this economy")

		app = Application(
			application_id = uuid4(),
			application_name = name,
			owner_id = owner_id,
			economy_id = economy.economy_id
		  )

		async with self._sessionmaker.begin() as session:
			session.add(app)
			session.add(
				Transaction(
					actor_id=actor.id, 
					action=Actions.UPDATE_ECONOMIES, 
					cud=CUD.CREATE,
					meta={
						"type": "APPLICATION",
						"application_id": app.application_id,
						"application_owner": owner_id
					}
				)
			)

		return app

	async def delete_application(self, actor: User, app_id: UUID, economy: Economy):
		"""
		Deletes an API application.
		
		:param actor: The actor of this action.
		:param app_id: The UUID of the application.
		:param economy: The economy in which the application is based in.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises NotFoundException: Raises a not found exception if the specified application does not exist.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_ECONOMIES, economy=economy):
			raise UnauthorizedException(f"You do not have permission to delete applications in this economy")

		application = await self.get_application(app_id)
		if not application:
			raise NotFoundException(f"No application with UUID ({app_id}) exists")

		async with self._sessionmaker.begin() as session:
			session.add(
				Transaction(
					actor_id=actor.id, 
					action=Actions.UPDATE_ECONOMIES, 
					cud=CUD.DELETE, 
					meta={
						"type": "APPLICATION",
						"application_id": application.application_id,
						"application_owner": application.owner_id
					}
				)
			)
			await session.delete(application)

	# === API Keys ===

	async def get_key(self, app: Application, ref_id: UUID) -> Optional[APIKey]:
		"""
		Fetch an API key by its application and custom reference UUID.
		
		:param app: The application which created the API key.
		:param ref_id: The custom reference UUID supplied by the application.
		:param _session: (optional) A pre-existing session to query with.
		
		:returns: The API key if it exists, else `None`.
		"""
		return await self._one_or_none(
			select(APIKey)
			.where(APIKey.application_id == app.application_id, APIKey.internal_app_id == ref_id)
			.options(joinedload(APIKey.application).joinedload(Application.economy))
		)

	async def get_key_by_id(self, key_id: int) -> Optional[APIKey]:
		"""
		Fetch an API key by its ID.
		
		:param key_id: The key ID.
		
		:returns: The API key if it exists, else `None`.
		"""
		return await self._one_or_none(
			select(APIKey)
			.where(APIKey.key_id == key_id)
			.options(joinedload(APIKey.application).joinedload(Application.economy))
		)

	async def initialize_key(self, app: Application, ref_id: UUID, issuer_id: int) -> APIKey:
		"""
		Initialize a new API key.
		
		:param application: The application creating this API key.
		:param ref_id: The custom reference UUID supplied by the application.
		:param issuer_id: The user ID of the issuer of this key.
		
		:returns: The new API key.
		"""
		async with self._sessionmaker.begin() as session:
			# check if a key with this ref. ID already exists
			current_key = await self.get_key(app, ref_id)
			if current_key:
				await session.delete(current_key)

			new_key = APIKey(application=app, internal_app_id=ref_id, issuer_id=issuer_id)

			session.add(new_key)
			session.add(
				Transaction(
					actor_id=issuer_id, 
					action=Actions.UPDATE_ECONOMIES, 
					cud=CUD.CREATE, 
					meta={
						"type": "API_KEY",
						"application_id": app.application_id,
						"ref_id": ref_id
					}
				)
			)

		return new_key

	async def delete_key(self, actor: User, key: APIKey):
		"""
		Delete an API key.
		
		:param actor: The actor of this action.
		:param key: The API key.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_ECONOMIES, economy=key.application.economy):
			raise UnauthorizedException(f"You do not have permission to delete keys in this economy")
		
		async with self._sessionmaker.begin() as session:
			session.add(
				Transaction(
					actor_id=actor.id, 
					action=Actions.UPDATE_ECONOMIES, 
					cud=CUD.DELETE, 
					meta={
						"type": "API_KEY",
						"application_id": key.application.application_id,
						"ref_id": key.internal_app_id
					}
				)
			)
			await session.execute(delete(Permission).where(Permission.user_id == key.key_id))
			await session.delete(key)

	# === Taxes ===

	async def get_tax_bracket(self, tax_name: str, economy: Economy) -> Optional[Tax]:
		"""
		Fetches a tax bracket by its name.
		
		:param tax_name: The name of the tax bracket.
		:param economy: The economy in which the tax bracket is based in.
		
		:returns: The tax bracket if it exists, else `None`.
		"""
		return await self._one_or_none(select(Tax).where(Tax.tax_name == tax_name, Tax.economy_id == economy.economy_id))

	async def get_tax_brackets(self, economy: Economy) -> Sequence[Tax]:
		"""
		Fetches all tax brackets in an economy.
		
		:param economy: The economy in which the tax brackets are based in.
		
		:returns: A list of tax brackets in the economy.
		"""
		async with self._sessionmaker() as session:
			return (
				await session.execute(
					select(Tax).where(Tax.economy_id == economy.economy_id)
				)
			).scalars().all()

	async def create_tax_bracket(self, actor: User, tax_name: str, affected_type: AccountType, tax_type: TaxType, bracket_start: int, bracket_end: Optional[int], rate: int, to_account: Account) -> Tax:
		"""
		Creates a new tax bracket.
		
		:param actor: The actor of this action.
		:param tax_name: The name of the new tax bracket.
		:param affected_type: The account type affected by this tax bracket.
		:param tax_type: The type of the new tax bracket.
		:param bracket_start: The starting balance amount for the tax bracket to apply.
		:param bracket_end: The final balance amount in which this tax bracket can apply, set to `None` for no ending limit.
		:param rate: The percentage rate of the new tax bracket.
		:param to_account: The account where tax revenue will be collected.
		:returns: The new tax bracket.

		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises AlreadyExistsException: Raises an already exists exception if a tax bracket exists with the same name provided.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_TAX_BRACKETS, economy=to_account.economy):
			raise UnauthorizedException("You do not have the permission to manage tax brackets in this economy")
		elif await self.get_tax_bracket(tax_name, to_account.economy):
			raise AlreadyExistsException("A tax bracket of that name already exists in this economy")

		kwargs = {
			"entry_id": uuid4(),
			"tax_name": tax_name,
			"affected_type": affected_type,
			"tax_type": tax_type,
			"bracket_start": bracket_start,
			"bracket_end": bracket_end,
			"rate": rate,
			"to_account_id": to_account.account_id,
			"economy_id": to_account.economy.economy_id
		}

		async with self._sessionmaker.begin() as session:
			tax_bracket = Tax(
				entry_id = uuid4(),
				tax_name = tax_name,
				affected_type = affected_type,
				tax_type = tax_type,
				bracket_start = bracket_start,
				bracket_end = bracket_end,
				rate = rate,
				to_account = to_account,
				economy = to_account.economy
			)

			session.add(tax_bracket)
			session.add(
				Transaction(
					actor_id = actor.id, 
					action = Actions.UPDATE_TAX_BRACKETS, 
					cud = CUD.CREATE, 
					economy_id = to_account.economy.economy_id, 
					destination_account_id = to_account.account_id,
					meta = make_serializable(kwargs)
				)
			)

			logger.log(LogLevels.Public, f"Economy: {to_account.economy.currency_name}\n<@!{actor.id}> created a new tax bracket by the name {tax_name}")

		return tax_bracket

	async def delete_tax_bracket(self, actor: User, tax_name: str, economy: Economy):
		"""
		Deletes a tax bracket.
		
		:param actor: The actor of this action.
		:param tax_name: The name of the tax bracket.
		:param economy: The economy in which the tax bracket is based in.
	
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises NotFoundException: Raises a not found exception if the specified tax bracket does not exist.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_TAX_BRACKETS, economy=economy):
			raise UnauthorizedException("You do not have the permission to manage tax brackets in this economy")
		elif not (tax_bracket := await self.get_tax_bracket(tax_name, economy)):
			raise NotFoundException(f"Tax bracket ({tax_name}) does not exist in this economy")

		async with self._sessionmaker.begin() as session:
			await session.delete(tax_bracket)
			session.add(
				Transaction(
					actor_id = actor.id,
					action = Actions.UPDATE_TAX_BRACKETS,
					cud = CUD.DELETE,
					economy_id = economy.economy_id,
					meta = make_serializable({
						"entry_id": tax_bracket.entry_id,
						"tax_name": tax_name
					})
				)
			)

			logger.log(LogLevels.Public, f"Economy: {economy.currency_name}\n<@!{actor.id}> deleted tax bracket {tax_name}")

	async def _perform_transaction_tax(self, amount: int, economy_id: UUID, affected_type: AccountType, session: AsyncSession) -> int:
		"""
		Performs all transaction taxes (VAT) of an economy on a transaction based on the amount transferred, and deposits the revenue earned to the tax bracket's recipient account.
		
		:returns: The total accumulated tax from the transaction.
		"""
		vat_taxes = (
			await session.execute(
				select(Tax)
				.options(
					joinedload(Tax.to_account).load_only(Account.account_id),
				)
				.where(
					Tax.tax_type == TaxType.VAT,
					Tax.economy_id == economy_id,
					Tax.affected_type == affected_type,
				)
				.order_by(Tax.bracket_start.desc())
			)
		).scalars().unique().all()

		total_accum = 0

		for vat_tax in vat_taxes:
			if amount <= vat_tax.bracket_start:
				continue

			taxable = (min(amount, vat_tax.bracket_end) if vat_tax.bracket_end else amount) - vat_tax.bracket_start

			if taxable > 0:
				accum = (taxable * vat_tax.rate) // 100
				await session.execute(update(Account).where(Account.account_id == vat_tax.to_account_id).values(balance=Account.balance + accum))
				total_accum += accum

		return total_accum

	async def perform_tax(self, actor: User, economy: Economy):
		"""
		Performs a tax cycle.
		
		:param actor: The actor of this action.
		:param economy: The economy in which the tax brackets are based in.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_TAX_BRACKETS, economy=economy):
			raise UnauthorizedException("You do not have the permission to trigger taxes in this economy")

		async with self._sessionmaker.begin() as session:
			logger.log(LogLevels.Public, f"Economy: {economy.currency_name}\n<@!{actor.id}> triggered a tax cycle")

			wealth_taxes = ( 
				await session.execute(
					select(Tax)
					.where(
						Tax.economy_id == economy.economy_id,
						Tax.tax_type.in_([TaxType.WEALTH_FLAT, TaxType.WEALTH_MARGINAL])
					)
					.options(joinedload(Tax.to_account))
					.order_by(Tax.bracket_start.desc())
				)
			).scalars()

			wealth_total = 0
			for wealth_tax in wealth_taxes:
				# This is actually so cool, it's like a switch statement in SQL
				# https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.case
				if wealth_tax.tax_type == TaxType.WEALTH_FLAT:
					tax_expr = case(
						(
							and_(Account.balance > wealth_tax.bracket_start, Account.balance <= wealth_tax.bracket_end if wealth_tax.bracket_end else true()),
							(Account.balance * wealth_tax.rate) // 100
						),
						else_=0
					)
				else:
					tax_expr = case(
						(
							and_(Account.balance > wealth_tax.bracket_start, Account.balance <= wealth_tax.bracket_end if wealth_tax.bracket_end else true()),
							((Account.balance - wealth_tax.bracket_start) * wealth_tax.rate) // 100
						),
						else_=0
					)

				accum: int = (
					await session.execute(
						select(func.sum(tax_expr.distinct()))
						.where(Account.account_type == Tax.affected_type, Account.deleted == False)
					)
				).scalar_one()

				await session.execute(
					update(Account)
					.where(Account.account_type == Tax.affected_type, Account.deleted == False)
					.values(balance=Account.balance - tax_expr)
				)

				wealth_tax.to_account.balance += accum
				wealth_total += accum

			logger.log(LogLevels.Public, f"Economy: {economy.currency_name}\nLevied {frmt(wealth_total)}{economy.currency_unit} in wealth taxes")

			income_taxes = ( 
				await session.execute(
					select(Tax)
					.where(
						Tax.economy_id == economy.economy_id,
						Tax.tax_type == TaxType.INCOME
					)
					.options(joinedload(Tax.to_account).load_only(Account.account_id))
					.order_by(Tax.bracket_start.desc())
				)
			).scalars()

			income_total = 0
			for income_tax in income_taxes:				
				tax_expr = case(
					(and_(Account.balance > income_tax.bracket_start, Account.balance <= income_tax.bracket_end if income_tax.bracket_end else true()),
						((Account.balance - income_tax.bracket_start) * income_tax.rate) // 100
					),
					else_=0
				)

				accum: int = (
					await session.execute(
						select(func.sum(tax_expr.distinct()))
						.where(Account.account_type == Tax.affected_type, Account.deleted == False)
					)
				).scalar_one()

				await session.execute(
					update(Account)
					.where(Account.account_type == Tax.affected_type, Account.deleted == False)
					.values(balance=Account.balance - tax_expr)
				)

				income_tax.to_account.balance += accum
				income_total += accum

			logger.log(LogLevels.Public, f"Economy: {economy.currency_name}\nLevied {frmt(income_total)}{economy.currency_unit} in income taxes")

			session.add(Transaction(
				actor_id = actor.id,
				action = Actions.PERFORM_TAXES,
				cud = CUD.UPDATE,
				economy_id = economy.economy_id
			))

	# === Permissions ===

	async def _reset_permission(self, user_id: int, permission: Permissions, session: AsyncSession, account: Optional[Account] = None, economy: Optional[Economy] = None):
		await session.execute(
			delete(Permission)
			.where(
				and_(
					Permission.permission == permission,
					Permission.user_id == user_id,
					or_(
						Permission.account_id == account.account_id if account else Permission.account_id.is_(None),
						Permission.economy_id == economy.economy_id if economy else Permission.economy_id.is_(None)
					)
				)
			)
		)
		
	async def _change_permission(self, user_id: int, permission: Permissions, session: AsyncSession, account: Optional[Account] = None, economy: Optional[Economy] = None, allowed: bool = True):
		if account and not economy:
			economy = account.economy

		await self._reset_permission(user_id, permission, session, account, economy)
		session.add(
			Permission(
				entry_id = uuid4(),
				user_id = user_id,
				permission = permission,
				account_id = (account.account_id if account is not None else None),
				economy_id = (economy.economy_id if economy is not None else None),
				allowed = allowed
			)
		)

	async def toggle_ephemeral(self, actor: discord.Member):
		"""
		Toggles the ephemeral message attribute for a member.
		
		:param actor: The member actor of this action.
		"""
		async with self._sessionmaker.begin() as session:
			await self._change_permission(actor.id, Permissions.USES_EPHEMERAL, session, allowed=not await self.has_permission(actor, Permissions.USES_EPHEMERAL))

	async def reset_permission(self, actor: User, user_id: int, permission: Permissions, account: Optional[Account] = None, economy: Optional[Economy] = None):
		"""
		Resets a permission back to its default state.
		
		:param actor: The actor of this action.
		:param user_id: The user ID of the affected user.
		:param permission: The permission to reset.
		:param account: (optional) The account constraint of the permission.
		:param economy: (optional) The economy constraint of the permission.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_PERMISSIONS, economy=economy):
			raise UnauthorizedException("You do not have permission to manage permissions here")

		async with self._sessionmaker.begin() as session:
			await self._reset_permission(user_id, permission, session, account, economy)
			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = economy.economy_id if economy is not None else None,
					target_account_id = account.account_id if account is not None else None,
					action = Actions.UPDATE_PERMISSIONS,
					cud = CUD.DELETE,
					meta = {
						"affected_id": user_id,
						"affected_permission": permission
					}
				)
			)

	async def change_permission(self, actor: User, user_id: int, permission: Permissions, account: Optional[Account] = None, economy: Optional[Economy] = None, allowed: bool = True):
		"""
		Changes a permission.
		
		:param actor: The actor of this action.
		:param user_id: The user ID of the affected user.
		:param permission: The permission to change.
		:param account: (optional) The account constraint of the permission.
		:param economy: (optional) The economy constraint of the permission.
		:param allowed: Whether the user is allowed this permission or not. Defaults to True.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_PERMISSIONS, economy=economy):
			raise UnauthorizedException("You do not have the permission to manage permissions here")

		async with self._sessionmaker.begin() as session:
			await self._change_permission(user_id, permission, session, account, economy, allowed)
			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = economy.economy_id if economy is not None else None,
					target_account_id = account.account_id if account is not None else None,
					action = Actions.UPDATE_PERMISSIONS,
					cud = CUD.UPDATE,
					meta = {
						"affected_id": user_id,
						"affected_permissions": [permission],
						"allowed": allowed
					}
				)
			)

	async def change_many_permissions(self, actor: User, user_id: int, permissions: list[Permissions], account: Optional[Account] = None, economy: Optional[Economy] = None, allowed: bool = True):
		"""
		Changes many permissions at once.
		
		:param actor: The actor of this action.
		:param user_id: The user ID of the affected user.
		:param permissions: The list of permissions to change.
		:param account: (optional) The account constraint of the permission.
		:param economy: (optional) The economy constraint of the permission.
		:param allowed: Whether the user is allowed these permissions or not. Defaults to True.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_PERMISSIONS, economy=economy):
			raise UnauthorizedException("You do not have permission to manage permissions here")

		async with self._sessionmaker.begin() as session:
			for permission in permissions:
				await self._change_permission(user_id, permission, session, account, economy, allowed)

			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = economy.economy_id if economy is not None else None,
					target_account_id = account.account_id if account is not None else None,
					action = Actions.UPDATE_PERMISSIONS,
					cud = CUD.UPDATE,
					meta = {
						"affected_id": user_id,
						"affected_permissions": permissions,
						"allowed": allowed
					}
				)
			)

	# === Economies ===

	async def get_economies(self) -> Sequence[Economy]:
		"""
		Fetches all economies the bot holds.
		
		:returns: A list of economies.
		"""
		async with self._sessionmaker() as session:
			return (await session.execute(select(Economy).options(selectinload(Economy.guilds)))).scalars().all()

	async def get_economy_by_name(self, currency_name: str) -> Optional[Economy]:
		"""
		Fetches an economy by its currency name.
		
		:param currency_name: The name of the economy's currency.
		
		:returns: The economy if it exists, else `None`.
		"""
		return await self._one_or_none(select(Economy).where(Economy.currency_name == currency_name).options(selectinload(Economy.guilds)))

	async def get_economy_by_id(self, economy_id: UUID) -> Optional[Economy]:
		"""
		Fetches an economy by its UUID.
		
		:param economy_id: The economy UUID.
		
		:returns: The economy if it exists, else `None`.
		"""
		return await self._one_or_none(select(Economy).where(Economy.economy_id == economy_id).options(selectinload(Economy.guilds)))

	async def create_economy(self, actor: discord.Member, currency_name: str, currency_unit: str) -> Economy:
		"""
		Creates a new economy tied to a guild.
	   
		:param actor: The member actor of this action.
		:param currency_name: The name of the new economy's currency.
		:param currency_unit: The unit/symbol of the new economy's currency.
		
		:returns: The new economy.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises AlreadyExistsException: Raises an already exists exception if an economy already exists with the specified currency name, or the actor's guild is already registered to an economy.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_ECONOMIES):
			raise UnauthorizedException("You do not have the permission to manage economies")
		elif await self.get_economy_by_name(currency_name):
			raise AlreadyExistsException(f"An economy by currency name ({currency_name}) already exists")
		elif await self.get_guild_economy(actor.guild.id):
			raise AlreadyExistsException(f"This guild is already registered to an economy")

		async with self._sessionmaker.begin() as session:
			economy = Economy(
				economy_id = uuid4(),
				currency_name = currency_name,
				currency_unit = currency_unit,
				owner_guild_id = actor.guild.id
			)

			session.add(economy)
			session.add(
				Guild(
					guild_id = actor.guild.id,
					economy = economy.economy_id
				)
			)
			session.add(
				Transaction(
					actor_id = actor.id,
					action = Actions.UPDATE_ECONOMIES,
					cud = CUD.CREATE,
					economy_id = economy.economy_id
				)
			)

			logger.log(LogLevels.Public, f"<@!{actor.id}> created the economy {currency_name}")

		return economy

	async def delete_economy(self, actor: User, economy: Economy):
		"""
		Deletes an economy.
		
		:param actor: The actor of this action.
		:param economy: The economy to be deleted.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_ECONOMIES):
			raise UnauthorizedException("You do not have the permission to manage economies")

		async with self._sessionmaker.begin() as session:
			await session.execute(delete(Guild).where(Guild.economy_id == economy.economy_id))
			await session.delete(economy)
			session.add(
				Transaction(
					actor_id = actor.id,
					action = Actions.UPDATE_ECONOMIES,
					cud = CUD.DELETE,
					economy_id = economy.economy_id
				)
			)

	# === Guilds ===

	async def get_guild_economy(self, guild_id: int) -> Optional[Economy]:
		"""
		Fetches the economy of a guild.
		
		:param guild_id: The guild's ID.
		
		:returns: The economy if it exists, else `None`.
		"""
		guild: Optional[Guild] = await self._one_or_none(select(Guild).where(Guild.guild_id == guild_id).options(joinedload(Guild.economy)))
		return guild.economy if guild else None

	@staticmethod
	async def get_guild_ids(economy: Economy) -> List[int]:
		"""
		Fetches the IDs of all guild members of an economy.
		
		:param economy: The economy which holds the guilds.
		
		:returns: A list of guild IDs.
		"""
		return [guild.guild_id for guild in economy.guilds]

	async def register_guild(self, actor: User, guild_id: int, economy: Economy):
		"""
		Registers a guild to an economy.
		
		:param actor: The actor of this action.
		:param guild_id: The guild's ID.
		:param economy: The economy which will hold the guild.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_ECONOMIES):
			raise UnauthorizedException("You do not have the permission to manage economies")

		async with self._sessionmaker.begin() as session:
			guild = await self._one_or_none(select(Guild).where(Guild.guild_id == guild_id), session=session)
			if guild:
				await session.delete(guild)

			session.add(
				Guild(
					guild_id = guild_id,
					economy_id = economy.economy_id
				)
			)

			logger.log(LogLevels.Public, f"<@!{actor.id}> registered the guild with id: {guild_id} to the economy {economy.currency_name}")

	async def unregister_guild(self, actor: User, guild_id: int):
		"""
		Unregisters a guild from its economy.
		
		:param actor: The actor of this action.
		:param guild_id: The guild's ID.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises AlreadyExistsException: Raises an already exists exception if the guild is the owner of an economy.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_ECONOMIES):
			raise UnauthorizedException("You do not have the permission to manage economies")

		async with self._sessionmaker.begin() as session:
			economies = (await session.execute(select(Economy).where(Economy.owner_guild_id == guild_id))).scalars().all()

			if len(economies) > 0:
				raise AlreadyExistsException("This guild is the owner guild of an economy, it cannot be unregistered")

			guild = await session.get(Guild, guild_id)
			if guild:
				await session.delete(guild) 
				logger.log(LogLevels.Public, f"<@!{actor.id}> unregistered the guild with id {guild_id} from its economy")

	# === Accounts ===

	async def get_user_account(self, user_id: int, economy: Economy) -> Optional[Account]:
		"""
		Fetches a user's account.
		
		:param user_id: The account owner's user ID.
		:param economy: The economy in which the account is based in.
		
		:returns: The account if it exists, else `None`.
		"""
		return await self._one_or_none(
			select(Account)
			.where(
				Account.owner_id == user_id,
				Account.account_type == AccountType.USER,
				Account.economy_id == economy.economy_id,
				Account.deleted == False
			)
			.options(joinedload(Account.economy), selectinload(Account.update_notifiers))
		)

	async def get_account_by_name(self, account_name: str, economy: Economy) -> Optional[Account]:
		"""
		Fetches an account by its name.
		
		:param account_name: The account name.
		:param economy: The economy in which the account is based in.
		
		:returns: The account if it exists, else `None`.
		"""
		return await self._one_or_none(
			select(Account)
			.where(
				Account.account_name == account_name,
				Account.economy_id == economy.economy_id,
				Account.deleted == False
			)
			.options(joinedload(Account.economy), selectinload(Account.update_notifiers))
		)

	async def get_account_by_id(self, account_id: UUID) -> Optional[Account]:
		"""
		Fetches an account by its ID.
		:param account_id: The account UUID.
		:returns: The account if it exists, else `None`.
		"""
		return await self._one_or_none(select(Account).where(Account.account_id == account_id).options(joinedload(Account.economy), selectinload(Account.update_notifiers)))

	async def create_account(self, actor: User, owner_id: Optional[int], economy: Economy, name: Optional[str] = None, account_type: AccountType = AccountType.USER) -> Account:
		"""
		Creates a new account.
		
		:param actor: The actor of this action.
		:param owner_id: (optional) The user ID of the new account's owner.
		:param economy: The economy in which the account is based in.
		:param name: (optional) The new account's name. Defaults to the owner's mention.
		:param account_type: The new account's type. Defaults to a user account.
		
		:returns: The new account.

		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises ValueError: Raises a value error if the name is too long (>64 characters).
		:raises AlreadyExistsException: Raises an already exists exception if:

		- the specified owner already owns a user account and the new account type is a user account, or
		- an account by the specified name already exists.
		"""
		if not await self.has_permission(actor, Permissions.OPEN_ACCOUNT, economy=economy):
			raise UnauthorizedException("You do not have the permission to open accounts")

		name = name if name else f"<@!{owner_id}>'s account"
		if len(name) > 64:
			raise ValueError("That name is too long")
		elif account_type == AccountType.USER and owner_id and owner_id == actor.id:
			if await self.get_user_account(owner_id, economy):
				raise AlreadyExistsException("You already have a user account")
		elif not await self.has_permission(actor, Permissions.OPEN_SPECIAL_ACCOUNT, economy=economy):
			raise UnauthorizedException("You do not have permission to open special accounts")
		elif name is not None and await self.get_account_by_name(name, economy):
			raise AlreadyExistsException(f"Account with name {name} already exists")

		async with self._sessionmaker.begin() as session:
			account = Account(account_id=uuid4(), account_name=name, owner_id=owner_id, account_type=account_type, balance=0, economy=economy, update_notifiers=[])
			session.add(account)
			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = economy.economy_id if economy else None,
					action = Actions.UPDATE_ACCOUNTS,
					cud = CUD.CREATE,
					meta = make_serializable({
						"account_type": account_type,
						"owner_id": owner_id
					})
				)
			)

		return account

	async def transfer_ownership(self, actor: User, account: Account, new_owner_id: int) -> Account:
		"""
		Transfers the ownership of an account to a new owner.
		
		:param actor: The actor of this action.
		:param account: The account to transfer ownership of.
		:param owner_id: The user ID of the account's new owner.
		
		:returns: The changed account.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.CLOSE_ACCOUNT, account=account):
			raise UnauthorizedException("You do not have the permission to transfer the ownership of this account")

		old_owner_id = account.owner_id
		async with self._sessionmaker.begin() as session:
			account.owner_id = new_owner_id

			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = account.economy.economy_id,
					target_account_id = account.account_id,
					action = Actions.UPDATE_ACCOUNTS,
					cud = CUD.UPDATE,
					meta = make_serializable({
						"old_owner_id": old_owner_id,
						"new_owner_id": new_owner_id
					})
				)
			)

			if account not in session:
				session.add(account)
			else:
				await session.refresh(account)

	async def rename_account(self, actor: User, account: Account, new_name: str):
		"""
		Renames an account.
		
		:param actor: The actor of this action.
		:param account: The account to be renamed.
		:param new_name: The new name of the account.

		:raises UnauthorizedException: Raises an unauthorized exception if the actor is not the account owner nor has the permission to rename the account.
		:raises ValueError: Raises a value error if a user account is provided.
		"""
		if not (await self.has_permission(actor, Permissions.CLOSE_ACCOUNT, account=account) or (account.owner_id and actor.id == account.owner_id)):
			raise UnauthorizedException("You do not have the permission to rename this account")
		elif account.account_type == AccountType.USER:
			raise UnauthorizedException("Cannot rename user accounts")

		async with self._sessionmaker.begin() as session:
			old_name = account.account_name
			account.account_name = new_name

			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = account.economy.economy_id,
					target_account_id = account.account_id,
					action = Actions.UPDATE_ACCOUNTS,
					cud = CUD.UPDATE,
					meta = make_serializable({
						"old_account_name": old_name,
						"new_account_name": new_name
					})
				)
			)

			if account not in session:
				session.add(account)
			else:
				await session.refresh(account)

	async def delete_account(self, actor: User, account: Account):
		"""
		Marks an account as deleted.
		
		:param actor: The actor of this action.
		:param account: The account to delete.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.CLOSE_ACCOUNT, account=account):
			raise UnauthorizedException("You do not have the permission to delete this account")

		async with self._sessionmaker.begin() as session:
			account.deleted = True

			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = account.economy.economy_id,
					target_account_id = account.account_id,
					action = Actions.UPDATE_ACCOUNTS,
					cud = CUD.DELETE
				)
			)

			if account not in session:
				session.add(account)
			else:
				await session.refresh(account)

	# === Transactions ===

	async def get_transaction_log(self, actor: User, account: Account, limit: Optional[int] = 10) -> Sequence[Transaction]:
		"""
		Fetches the transactions of an account.
		
		:param actor: The actor of this action.
		:param account: The account to fetch transactions for.
		:param limit: (optional) The number of transactions to fetch. Defaults to 10. Set to `None` to fetch all transactions (but be warned that this is an expensive operation).
		
		:returns: A list of transactions.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.VIEW_BALANCE, account=account):
			raise UnauthorizedException("You do not have the permission to view the transaction log of this account")

		async with self._sessionmaker() as session:
			return (
				await session.execute(
					select(Transaction)
					.options(
						load_only(
							Transaction.transaction_id,
							Transaction.actor_id,
							Transaction.target_account_id,
							Transaction.destination_account_id,
							Transaction.action,
							Transaction.amount,
							Transaction.timestamp
						),
						joinedload(Transaction.target_account),
						joinedload(Transaction.destination_account)
					)
					.where(
						(Transaction.target_account_id == account.account_id) | (Transaction.destination_account_id == account.account_id),
						Transaction.action == Actions.TRANSFER
					)
					.limit(limit)
					.order_by(Transaction.timestamp.desc())
				)
			).scalars().all()

	async def create_reccuring_transfer(self, actor: User, 
		from_account: Account,
		to_account: Account,
		amount: int,
		payment_interval: int,
		number_of_payments: Optional[int] = None,
		transaction_type: TransactionType = TransactionType.INCOME) -> RecurringTransfer:
		"""
		Creates a new recurring transfer, which begins transferral from the next payment interval.
		
		:param actor: The actor of this action.
		:param from_account: The account to be transferred from.
		:param to_account: The account to transfer to.
		:param amount: The amount to transfer, in cents.
		:param payment_interval: How often the transfer should occur, in days.
		:param number_of_payments_left: The number of recurring transfers to occur, defaults to `None` which indicates an infinite recurring transfer granted that the amount to be transferred is available.
		:param transaction_type: The type of the transaction, defaults to an income transaction.
		
		:returns: The new recurring transfer.

		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.CREATE_RECURRING_TRANSFERS, account=from_account):
			raise UnauthorizedException("You do not have the permission to create recurring transfers on this account")

		async with self._sessionmaker.begin() as session:
			rec_transfer = RecurringTransfer(
				entry_id = uuid4(),
				authorisor_id = actor.id,
				from_account_id=from_account.account_id,
				to_account_id = to_account.account_id,
				amount = amount,
				last_payment_timestamp = time.time(),
				payment_interval = payment_interval * DAY_TO_SECOND,
				transaction_type = transaction_type,
				number_of_payments_left = number_of_payments
			)

			session.add(rec_transfer)

		return rec_transfer

	async def _perform_transaction(self, actor: User,
		from_account: Account,
		to_account: Account,
		amount: int,
		session: AsyncSession,
		transaction_type: TransactionType = TransactionType.INCOME):
		if from_account not in session:
			session.add(from_account)
		if to_account not in session:
			session.add(to_account)

		transaction = Transaction(
			actor_id = actor.id,
			economy_id = from_account.economy_id,
			target_account = from_account,
			destination_account = to_account,
			action = Actions.TRANSFER,
			cud = CUD.UPDATE,
			amount = amount
		)
		session.add(transaction)

		if transaction_type == TransactionType.INCOME:
			to_account.income_to_date += amount

		tax_amount = await self._perform_transaction_tax(amount, from_account.economy_id, from_account.account_type, session)
		from_account.balance -= amount
		to_account.balance += (amount - tax_amount)

		await session.refresh(from_account, ["economy", "update_notifiers"])
		await session.refresh(to_account, ["economy", "update_notifiers"])

	async def perform_transaction(self, actor: User, 
		from_account: Account,
		to_account: Account,
		amount: int,
		transaction_type: TransactionType = TransactionType.INCOME):
		"""
		Performs a transaction from one account to another, accounting for tax.
		
		:param actor: The actor of this action.
		:param from_account: The account to be transferred from.
		:param to_account: The account to transfer to.
		:param amount: The amount to transfer, in cents.
		:param transaction_type: The type of the transaction, defaults to an income transaction.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises ValueError: Raises a value error if the account transferring has insufficient funds.
		"""
		if not await self.has_permission(actor, Permissions.TRANSFER_FUNDS, account=from_account):
			raise UnauthorizedException("You do not have the permission to transfer funds on this account")
		elif from_account.economy_id != to_account.economy_id:
			raise BackendException("Cannot transfer between different economies")
		elif from_account.balance < amount:
			raise ValueError("You do not have sufficient funds to transfer from that account")
		elif from_account.account_id == to_account.account_id:
			return

		async with self._sessionmaker.begin() as session:
			from_account = await session.merge(from_account) # make sure the session does not try to pull up the economy when it is already eager loaded
			to_account = await session.merge(to_account)

			transaction = Transaction(
				actor_id = actor.id,
				economy_id = from_account.economy_id,
				target_account = from_account,
				destination_account = to_account,
				action = Actions.TRANSFER,
				cud = CUD.UPDATE,
				amount = amount
			)
			session.add(transaction)

			if transaction_type == TransactionType.INCOME:
				to_account.income_to_date += amount

			tax_amount = await self._perform_transaction_tax(amount, from_account.economy_id, from_account.account_type, session)
			from_account.balance -= amount
			to_account.balance += (amount - tax_amount)

		log = LogLevels.Private if not await self.has_permission(actor, Permissions.GOVERNMENT_OFFICIAL) else LogLevels.Public

		logger.log(log, f"Economy: {from_account.economy.currency_name}\n<@!{actor.id}> transferred {frmt(amount)} from {from_account.account_name} to {to_account.account_name}. Transaction type: {transaction_type.name.upper()}")
		await self.notify_users(to_account.get_update_notifiers(), f"<@!{actor.id}> transferred {frmt(amount)} from {from_account.account_name} to {to_account.account_name}, \nit's new balance is {to_account.get_balance()}", "Balance Update")
		await self.notify_users(from_account.get_update_notifiers(), f"<@!{actor.id}> transferred {frmt(amount)} from an account you watch ({from_account.account_name}), to {to_account.account_name}\n{from_account.account_name}'s new balance is {from_account.get_balance()}", "Balance Update")

	# === Fund management ===

	async def print_funds(self, actor: User, to_account: Account, amount: int):
		"""
		Prints funds to an account.
		
		:param actor: The actor of this action.
		:param to_account: The account to print funds to.
		:param amount: The amount to print, in cents.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_FUNDS, economy=to_account.economy):
			raise UnauthorizedException("You do not have the permission to print funds")

		async with self._sessionmaker.begin() as session:
			session.add(to_account)
			to_account.balance += amount
			
			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = to_account.economy.economy_id,
					destination_account_id = to_account.account_id,
					action = Actions.MANAGE_FUNDS,
					cud = CUD.CREATE,
					amount = amount
				)
			)

		logger.log(LogLevels.Public, f"Economy: {to_account.economy.currency_name}\n<@!{actor.id}> printed {frmt(amount)} to {to_account.account_name}")
		await self.notify_users(to_account.get_update_notifiers(), f"<@!{actor.id}> printed {frmt(amount)} to {to_account.account_name},\nit\'s new balance is {to_account.get_balance()}", "Balance Update")

	async def remove_funds(self, actor: User, from_account: Account, amount: int):
		"""
		Removes funds from an account.
		
		:param actor: The actor of this action.
		:param to_account: The account to remove funds from.
		:param amount: The amount to print, in cents.

		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		:raises ValueError: Raises a value error if there are not sufficient funds to remove from the account.
		"""
		if not await self.has_permission(actor, Permissions.MANAGE_FUNDS, economy=from_account.economy):
			raise UnauthorizedException("You do not have the permission to print funds")
		elif from_account.balance < amount:
			raise ValueError("There are not sufficient funds in this account to perform this action")

		async with self._sessionmaker.begin() as session:
			if from_account not in session:
				session.add(from_account)

			from_account.balance -= amount

			session.add(
				Transaction(
					actor_id = actor.id,
					economy_id = from_account.economy.economy_id,
					destination_account_id = from_account.account_id,
					action = Actions.MANAGE_FUNDS,
					cud = CUD.DELETE,
					amount = amount
				)
			)

			await session.refresh(from_account, ["economy", "update_notifiers"])

		logger.log(LogLevels.Public, f"Economy: {from_account.economy.currency_name}\n<@!{actor.id}> removed {frmt(amount)} from {from_account.account_name}")
		await self.notify_users(from_account.get_update_notifiers(), f"<@!{actor.id}> removed {frmt(amount)} from {from_account.account_name},\nit\'s new balance is {from_account.get_balance()}", "Balance Update")

	# === Notifications ===

	async def _unsubscribe(self, user: User, account: Account, session: AsyncSession):
		for notifier in account.update_notifiers:
			if notifier.owner_id == user.id:
				await session.delete(notifier)

	async def subscribe(self, actor: User, account: Account):
		"""
		Subscribes to an account's balance updates.
		
		:param actor: The actor of this action.
		:param account: The account to subscribe to.
		
		:raises UnauthorizedException: Raises an unauthorized exception if the actor is unauthorized to perform this action.
		"""
		if not await self.has_permission(actor, Permissions.VIEW_BALANCE, account=account):
			raise UnauthorizedException("You do not have the permission to subscribe to this account's updates")

		async with self._sessionmaker.begin() as session:
			await self._unsubscribe(actor, account, session)
			session.add(
				BalanceUpdateNotifier(
					notifier_id = uuid4(),
					owner_id = actor.id,
					account_id = account.account_id
				)
			)

	async def unsubscribe(self, actor: User, account: Account):
		"""
		Unsubscribes from an account's balance updates.
		
		:param actor: The actor of this action.
		:param account: The account to subscribe to.
		"""
		async with self._sessionmaker.begin() as session:
			await self._unsubscribe(actor, account, session)

	async def notify_user(self, user_id: int, message: str, title: str, thumbnail: Optional[str] = None):
		"""
		Send a user an embed notification.
		
		:param user_id: The user's ID.
		:param message: The notification message.
		:param title: The notification title.
		:param thumbnail: (optional) The thumbnail URL of the notifiaction embed.
		"""
		logger.warning(f"Backend failed to message user: {user_id}")

	async def notify_users(self, user_ids: List[int], *args, **kwargs):
		"""
		Shorthand for sending notifications to many users in bulk similar to `notify_user`.
		
		:param user_id: A list of user IDs.
		"""
		for user_id in user_ids:
			await self.notify_user(user_id, *args, **kwargs)

	# === Discord parity ===

	async def get_member(self, user_id: int, guild_id: int):
		"""
		Fetches a Discord member by their ID, in addition to their guild ID.

		:param user_id: The member's user ID.
		:param guild_id: The member's guild ID.

		:returns: The member if it exists, else `None`.
		"""
		pass

	async def get_user_dms(self, user_id: int):
		"""
		Fetches a Discord member's private mesasge channel.

		:param user_id: The member's user ID.

		:returns: The channel if it exists, else `None`.
		"""
		pass

	# === Context manager ===

	async def close(self):
		"""Dispose of the engine and close session."""
		await self.engine.dispose()

	async def __aenter__(self):
		await self.initalize() # ENSURE tables are created
		return self
	
	async def __aexit__(self, exc_type, exc_v, _____):
		# If it returns True (or anything that evaluates as truthy) then the system will assume
		# that the exception has been handled and corrected for, and will not propagate it any further.
		# If it returns False, None, anything that evaluates as falsy, or nothing at all then the exception will continue to propagate.
		# https://bbc.github.io/cloudfit-public-docs/asyncio/asyncio-part-3.html
		try:
			if isinstance(exc_v, (KeyboardInterrupt, asyncio.CancelledError)):
				return

			if exc_v:
				print(exc_type)
				if issubclass(exc_type, BackendException):
					raise exc_v
				else:
					exc = BackendException(exc_v)
					raise exc from exc_v
		finally:
			await self.close()

if __name__ == "__main__":
	import time

	database_uri = "sqlite+aiosqlite:///database.db"
	async def main():
		async with Backend(database_uri, poolclass=AsyncAdaptedQueuePool, echo=True) as backend:
			stub = StubUser(809875420350119958)
			stub.roles = [StubUser(1273953959458902129)]
			start = time.perf_counter()

			econ = await backend.get_economy_by_name("tau")
			if econ:
				acc = await backend.get_account_by_name("<@!809875420350119958> 's account", econ)
				if acc:
					result = await backend.get_transaction_log(stub, acc)
					print(f"Result: {result} in {(time.perf_counter() - start) * 1000:.6f}ms")

	asyncio.run(main())