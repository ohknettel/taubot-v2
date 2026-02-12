import traceback
from discord.ext import commands, tasks
from utils import generate_transaction_csv, load_config, USER_MENTION_REGEX
from middleman import DiscordBackendInterface, logger as backend_logger, backend as bknd, AsyncAdaptedQueuePool
from datetime import time as datetime_time, datetime
from typing import Optional
from enum import IntEnum
from logging.handlers import TimedRotatingFileHandler

import asyncio
import aiohttp
import discord
import time
import re
import logging
import textwrap
import api
import sys
import io
import os

# Regexes
CURRENCY_REGEX = re.compile(r"^[0-9]*([.,][0-9]{1,2}0*)?$")

# Logging
formatter = logging.Formatter("[%(asctime)s] [%(name)s] [%(levelname)s]: %(message)s")
logger = logging.getLogger(os.path.basename(__file__).split(".")[0])

stream = logging.StreamHandler()
stream.setFormatter(formatter)
stream.setLevel(logging.INFO)

logger.addHandler(stream)
logger.setLevel(logging.INFO)

for lgr in [backend_logger, api.logger]:
	handler = TimedRotatingFileHandler(f"logs/{lgr.name}.log", "midnight", backupCount=15, encoding="utf-8") # daily logs for 15 days
	handler.setFormatter(formatter)
	handler.setLevel(logging.INFO)

	lgr.addHandler(handler)
	lgr.setLevel(logging.INFO)

class WebhookHandler(logging.Handler):
	def __init__(self, webhook_url, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._webhook_url = webhook_url
		self.session = aiohttp.ClientSession()

	async def send(self, *args, **kwargs):
		wh = discord.Webhook.from_url(self._webhook_url, session=self.session)
		await wh.send(*args, **kwargs)

	def emit(self, record: logging.LogRecord):
		embed = discord.Embed(colour=discord.Colour.blue())
		embed.add_field(name=record.name, value=record.message, inline=False)
		asyncio.get_event_loop().create_task(self.send(embed=embed))

class LevelFilter(logging.Filter):
	def __init__(self, level: int):
		self.level = level

	def filter(self, record):
		return record.levelno == self.level

def setup_webhook(logger: logging.Logger, webhook_url: str, levelno: int):
	"""
	Setups a Discord webhook to receive log records.

	:param logger: The logger instance.
	:param webhook_url: The Discord webhook URL.
	:param levelno: The level number of records to send.
	"""
	handler = WebhookHandler(webhook_url)
	handler.setLevel(levelno)
	handler.addFilter(LevelFilter(levelno))
	logger.addHandler(handler)

# Views
class ConfirmationView(discord.ui.View):
	def __init__(self):
		super().__init__()
		self.confirmation = False

	@discord.ui.button(label="Yes", style=discord.ButtonStyle.green)
	async def yes(self, interaction: discord.Interaction, _):
		await interaction.response.defer()
		self.confirmation = True
		self.stop()

	@discord.ui.button(label="No", style=discord.ButtonStyle.red)
	async def no(self, interaction: discord.Interaction, _):
		await interaction.response.defer()
		self.stop()

class PaginatorView(discord.ui.View):
	message: discord.Message

	@classmethod
	def segment_by_length(cls, items: list[str], max_length: int = 1024, sep: str = '\n') -> list[list[str]]:
		chunks = []
		current_chunk = []
		current_length = 0 

		for item in items:
			item_length = len(item) + len(sep) if current_chunk else len(item)
			if current_length + item_length > max_length:
				chunks.append(current_chunk)
				current_chunk = [item]
				current_length = len(item)
			else:
				current_chunk.append(item)
				current_length += item_length

		if current_chunk:
			chunks.append(current_chunk)

		return chunks

	def __init__(self, embeds: list[discord.Embed]):
		super().__init__()
		self.embeds = embeds
		self.index = 0

		if len(self.embeds) > 0:
			self.counter.label = f"{self.index + 1}/{len(self.embeds)}"

	def _update_button_states(self):
		last_index = len(self.embeds) - 1
		is_first = self.index <= 0
		is_last = self.index >= last_index

		self.first_btn.disabled = is_first
		self.previous_btn.disabled = is_first
		self.next_btn.disabled = is_last
		self.last_btn.disabled = is_last

	async def update_item(self, new_index: int):
		self.index = max(0, min(new_index, len(self.embeds) - 1))
		self._update_button_states()
		self.counter.label = f"{self.index + 1}/{len(self.embeds)}"

		if self.message:
			self.message = await self.message.edit(embed=self.embeds[self.index], view=self)

	@discord.ui.button(emoji="⏪", style=discord.ButtonStyle.red) # reverse emoji
	async def first_btn(self, interaction: discord.Interaction, _):
		await interaction.response.defer()
		await self.update_item(0)

	@discord.ui.button(emoji="⬅️", style=discord.ButtonStyle.green) # left arrow emoji
	async def previous_btn(self, interaction: discord.Interaction, _):
		await interaction.response.defer()
		await self.update_item(self.index - 1)

	@discord.ui.button(label="0/0", style=discord.ButtonStyle.grey, disabled=True)
	async def counter(self, __interaction__: discord.Interaction, _):
		pass

	@discord.ui.button(emoji="➡️", style=discord.ButtonStyle.green) # right arrow emoji
	async def next_btn(self, interaction: discord.Interaction, _):
		await interaction.response.defer()
		await self.update_item(self.index + 1)

	@discord.ui.button(emoji="⏩", style=discord.ButtonStyle.red) # ff emoji
	async def last_btn(self, interaction: discord.Interaction, _):
		await interaction.response.defer()
		await self.update_item(len(self.embeds) - 1)

# Discord bot
init_time = time.time()
tick_time = datetime_time(hour=0, minute=0) # Midnight, UTC
login_map: dict[int, bknd.Account] = {}
config = {}

class Taubot(commands.Bot):
	backend: DiscordBackendInterface

	@tasks.loop(time=tick_time)
	async def tick(self):
		"""
		Triggers a tick in the backend.
		"""
		await self.backend.tick()
		await dump(self, True)

	@tick.before_loop
	async def pretick(self):
		await self.wait_until_ready()

	async def close(self):
		"""
		Closes the bot and backend instances.
		"""
		await self.backend.close()
		return await super().close()

	async def setup_hook(self):
		"""
		Function called between startup and connecting to the gateway.
		"""
		await self.add_cog(CommandsCog(self))

		use_api = bool(config.get("api", False))
		if use_api:
			asyncio.create_task(api.run_api(self.backend, self))
			logger.info("Successfully started the API")

		syncing = bool(config.get("sync", False))
		if syncing:
			test_guild_id = config.get("sync_guild")
			test_guild = discord.Object(id=int(test_guild_id)) if test_guild_id and int(test_guild_id) else None

			commands = await self.tree.sync(guild=test_guild)
			logger.info(f"Synced {len(commands)} commands")

		self.tick.start()

	async def get_account(self, user_id: int, economy: bknd.Economy) -> Optional[bknd.Account]:
		"""
		Fetches a member's currenty logged in account, or the account the member owns if they are not logged in.

		:param user_id: The member's ID.
		:param economy: The guild economy

		:returns: The account if it exists, else `None`.
		"""
		account = login_map.get(user_id)
		if not account:
			return await self.backend.get_user_account(user_id, economy)

		await self.backend.refresh(account)
		return account

	async def get_account_by_name(self, name: str, economy: bknd.Economy) -> Optional[bknd.Account]:
		"""
		Fetches an account by its name, resolving Discord mentions.

		:param name: The name or mention content.
		:param economy: The economy the account is based in.

		:returns: The account if it exists, else `None`.
		"""
		name = name.strip()

		if (match := USER_MENTION_REGEX.match(name)):
			_id = int(match.group(1))
			return await self.backend.get_user_account(_id, economy)
		else:
			return await self.backend.get_account_by_name(name, economy)

async def dump(bot: Taubot, automatic: bool = False):
	"""
	Triggers a dump of accounts and transactions as a CSV file to be sent through the private webhook.

	:param bot: The bot instance.
	:param automatic: Whether the dump is automatic or not.

	:meta private:
	"""
	try:
		backend = bot.backend
		with io.StringIO() as buf, io.StringIO() as buf2:
			accounts_f = discord.File(await backend.dump_accounts_csv(buf), filename="accounts.csv") # pyright: ignore
			trans_f = discord.File(await backend.dump_transactions_csv(buf2), filename="transactions.csv") # pyright: ignore

			if private_webhook_url and len(private_webhook_url) > 0:
				timestamp = int(datetime.now().timestamp())
				await discord.Webhook.from_url(private_webhook_url, client=bot).send(
					content=f"Database dump, triggered {'manually' if not automatic else 'automatically'} at <t:{timestamp}>",
					files=[accounts_f, trans_f]
				)
	except Exception:
		traceback.print_exc()

# Utils
class ParseException(Exception):
	pass

class PermissionState(IntEnum):
	DISALLOWED = 0
	ALLOWED = 1
	DEFAULT = 2

def parse_amount(amount: str) -> int:
	"""
	Parses a string amount to cents.

	:param amount: The amount to parse.
	:returns: The amount in cents.
	"""

	if not CURRENCY_REGEX.match(amount):
		raise ParseException(
			"Invalid currency value, please ensure you do not have more than two decimal places of precision")
	parts = amount.split('.')
	if len(parts) == 1:
		return int(parts[0]) * 100
	elif len(parts) == 2:
		part = parts[1]
		part = part.rstrip('0')
		part = part.ljust(2, '0')
		return (int(parts[0]) * 100) + int(part)
	else:
		raise ParseException("Invalid currency value")

def create_embed(title: str, message: str, colour: Optional[discord.Colour | int] = None, with_footer: bool = False) -> discord.Embed:
	"""
	Shorthand utility to create an embed.

	:param title: The embed title.
	:param message: The embed message.
	:param colour: The embed colour.
	:param with_footer: Whether to include the default bot footer.

	:returns: The embed.
	"""

	colour = colour if colour else discord.Colour.blue()
	embed = discord.Embed(colour=colour).add_field(name=title, value=message)

	if with_footer:
		embed.set_footer(text="This message was sent by a bot and is probably highly important")

	return embed

# Commands
class CommandsCog(commands.Cog):
	def __init__(self, bot: Taubot):
		self.bot = bot
		self.backend = self.bot.backend
		self.bot.tree.error(self.on_app_command_error)

	@commands.Cog.listener()
	async def on_ready(self):
		logger.info(f"Logged in as {self.bot.user}")

	@commands.Cog.listener("on_app_command_error")
	async def on_app_command_error(self, interaction: discord.Interaction, error: discord.app_commands.AppCommandError):
		if isinstance(error, discord.app_commands.MissingPermissions):
			embed = discord.Embed(
				description=f"You are not authorized to run this command.",
				colour=discord.Colour.red()
			)

			await interaction.response.send_message(embed=embed, ephemeral=True)
		else:
			embed = discord.Embed(
				description=f"{error}",
				colour=discord.Colour.red()
			)

			traceback.print_exception(type(error), error, error.__traceback__)
			await interaction.response.send_message(embed=embed, ephemeral=True)

	async def interaction_check(self, interaction: discord.Interaction): # pyright: ignore
		if interaction.type == discord.InteractionType.application_command and not interaction.guild:
			await interaction.response.send_message(
				embed=create_embed(
					"Running commands in DMs is not supported",
					"This restriction has been placed for safety reasons until further notice.",
					discord.Colour.red()
				)
			)
			return False
		return True

	async def _get_member(self, interaction: discord.Interaction) -> Optional[discord.Member]:
		if not isinstance(interaction.user, discord.Member):
			await interaction.response.send_message(
				embed=create_embed(
					"Running commands in DMs is not supported",
					"This restriction has been placed for safety reasons until further notice.",
					discord.Colour.red()
				)
			)

			return None
		return interaction.user

	@discord.app_commands.describe(economy_name="The name of the new economy's currency", currency_unit="The unit/symbol of the new economy's currency")
	@discord.app_commands.command(description="Creates a new economy")
	async def create_economy(self, interaction: discord.Interaction, economy_name: str, currency_unit: str):
		responder = await self.backend.get_responder(interaction)
		member = await self._get_member(interaction)
		if not member:
			return

		try:
			await self.backend.create_economy(member, economy_name, currency_unit)
			await responder("Successfully created a new economy")
		except Exception as e:
			await responder(f"Could not create a new economy: {e}", colour=discord.Colour.red())

	@discord.app_commands.command(description="List all economies hosted by the bot")
	async def list_economies(self, interaction: discord.Interaction):
		responder = await self.backend.get_responder(interaction)
		economies = await self.backend.get_economies()

		embed = discord.Embed(colour=discord.Colour.blue())

		names, units, guilds = [], [], []
		for e in economies:
			names.append(e.currency_name)
			units.append(e.currency_unit)
			guilds.append(str(len(e.guilds)))
		
		embed \
		.add_field(name="Economy name", value='\n'.join(names)) \
		.add_field(name="Currency unit", value='\n'.join(units)) \
		.add_field(name="Guilds present", value='\n'.join(guilds))

		await responder(embed=embed)

	@discord.app_commands.describe(economy_name="The name of the economy's currency")
	@discord.app_commands.command(description="Registers a named economy to this guild")
	async def join_economy(self, interaction: discord.Interaction, economy_name: str):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_economy_by_name(economy_name)
		if not economy:
			return await responder("Economy not found", colour=discord.Colour.red())

		try:
			await self.backend.register_guild(interaction.user, interaction.guild_id or -1, economy)
			await responder(f"Successfully joined economy `{economy_name}`")
		except Exception as e:
			await responder(f"Could not join economy `{economy_name}`: {e}", colour=discord.Colour.red())

	@discord.app_commands.command(description="Unregisters this guild from its economy")
	async def leave_economy(self, interaction: discord.Interaction):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		try:
			await self.backend.unregister_guild(interaction.user, interaction.guild_id or -1)
			await responder(f"Successfully left economy `{economy.currency_name}`")
		except Exception as e:
			await responder(f"Could not successfully leave economy `{economy.currency_name}`: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(economy_name="The name of the economy's currency", skip_confirmation="Whether to skip the confirmation view")
	@discord.app_commands.command(description="Deletes an economy")
	async def delete_economy(self, interaction: discord.Interaction, economy_name: str, skip_confirmation: bool = False):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_economy_by_name(economy_name)
		confirm = skip_confirmation

		if not economy:
			return await responder("Economy not found", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.MANAGE_ECONOMIES, economy=economy):
			return await responder("Could not delete economy: You do not have the permission to manage economies", colour=discord.Colour.red())

		if not skip_confirmation:
			confirm_view = ConfirmationView()
			await responder(f"Are you sure you want to delete economy `{economy.currency_name}`?", view=confirm_view)
			await confirm_view.wait()
			confirm = confirm_view.confirmation
			
		if confirm:
			try:
				await self.backend.delete_economy(interaction.user, economy)
				await responder(f"Successfully deleted economy `{economy.currency_name}`", edit=True, view=None)
			except Exception as e:
				await responder(f"Could not delete economy `{economy.currency_name}`: {e}", colour=discord.Colour.red(), edit=True, view=None)
		else:
			await responder(f"Cancelled operation", edit=True, view=None)

	@discord.app_commands.command(description="Opens a user account in this guild's economy")
	async def open_account(self, interaction: discord.Interaction):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		try:
			await self.backend.create_account(interaction.user, interaction.user.id, economy)
			await responder(f"Your account has been created successfully")
		except Exception as e:
			await responder(f"Could not create account: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(
		account_name="The name of the new account",
		owner="The user or role which will own this account, optional",
		account_type="The account type of the account"
	)
	@discord.app_commands.command(description="Opens a special account in this guild's economy")
	async def open_special_account(self, interaction: discord.Interaction, account_name: str, owner: discord.Member | discord.Role | None, account_type: bknd.AccountType):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		try:
			await self.backend.create_account(interaction.user, owner.id if owner else owner, economy, account_name, account_type)
			await responder(f"Account created successfully")
		except Exception as e:
			await responder(f"Could not create account: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(
		new_owner="The user/role to transfer ownership to",
		account="The account to transfer ownership of, defaults to the current logged in account"
	)
	@discord.app_commands.command(description="Transfers the ownership of an account")
	async def transfer_ownership(self, interaction: discord.Interaction, new_owner: discord.Member | discord.Role, account: Optional[str] = None):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		member = await self._get_member(interaction)
		if not member:
			return

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.CLOSE_ACCOUNT, account=acc):
			return await responder("Could not close account: You do not have the permission to transfer the ownership of this account", colour=discord.Colour.red())

		confirm_view = ConfirmationView()
		await responder(message=textwrap.dedent(f"""
			Are you sure you want to transfer the ownership of this account to {new_owner.mention}?
			You will not be able to:
			- login as the account or close it
			- view the account's balance
			- transfer funds from the account, including creating recurring transfers
			- receive updates about the account's balance
			In addition, you will be logged out of the account
		"""), view=confirm_view)
		await confirm_view.wait()

		if confirm_view.confirmation:
			try:
				await self.backend.transfer_ownership(interaction.user, acc, new_owner.id)

				user_acc = await self.backend.get_account_from_interaction(interaction)
				if user_acc:
					login_map[interaction.user.id] = user_acc

				[login_map.pop(k, None) for k, v in login_map.items() if v.account_id == acc.account_id]

				await responder(f"Successfully transferred account ownership to {new_owner.mention}", edit=True, view=None)
			except Exception as e:
				await responder(f"Could not transfer account ownership: {e}", colour=discord.Colour.red(), edit=True, view=None)
		else:
			await responder(f"Cancelled operation", edit=True, view=None)

	@discord.app_commands.describe(account="The account to close, defaults to the current logged in account", skip_confirmation="Whether to skip the confirmation view")
	@discord.app_commands.command(description="Closes an account")
	async def close_account(self, interaction: discord.Interaction, account: Optional[str] = None, skip_confirmation: bool = False):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
		confirm = skip_confirmation

		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.CLOSE_ACCOUNT, account=acc):
			return await responder("Could not close account: You do not have the permission to close this account", colour=discord.Colour.red())

		if not skip_confirmation:
			confirm_view = ConfirmationView()
			await responder(f"Are you sure you want to close this account?", view=confirm_view)
			await confirm_view.wait()
			confirm = confirm_view.confirmation
			
		if confirm:
			try:
				await self.backend.delete_account(interaction.user, acc)
				[login_map.pop(k, None) for k, v in login_map.items() if v.account_id == acc.account_id]
				await responder(f"Successfully closed account", edit=True, view=None)
			except Exception as e:
				await responder(f"Could not close account: {e}", colour=discord.Colour.red(), edit=True, view=None)
		else:
			await responder(f"Cancelled operation", edit=True, view=None)

	@discord.app_commands.describe(name="The new account name", account="The account to rename, defaults to the current logged in account")
	@discord.app_commands.command(description="Renames an account")
	async def rename_account(self, interaction: discord.Interaction, name: str, account: Optional[str] = None):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)

		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())
		
		try:
			await self.backend.rename_account(interaction.user, acc, name)
			await responder(f"Successfully renamed account")
		except Exception as e:
			await responder(f"Could not rename account: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(account="The account to login to, defaults to your user account if not supplied")
	@discord.app_commands.command(description="Login as an account that is not yours, or into your account if no arguments are provided")
	async def login(self, interaction: discord.Interaction, account: Optional[str] = None):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)

		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.LOGIN_AS_ACCOUNT, account=acc):
			return await responder("You do not have the permission to log into this account", colour=discord.Colour.red())

		login_map[interaction.user.id] = acc
		await responder(f"You have now logged in as {acc.account_name}\nTo log back into your user account simply run `/login` without any arguments")

	@discord.app_commands.command(description="View the account you are acting as")
	async def whoami(self, interaction: discord.Interaction):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account(interaction.user.id, economy)
		if not acc:
			return await responder("You are not logged into an account", colour=discord.Colour.red())
		else:
			return await responder(f"You are currently acting as {acc.account_name}")

	@discord.app_commands.describe(account="The account to view balance of, defaults to the current logged in account")
	@discord.app_commands.command(description="View the balance of an account")
	async def balance(self, interaction: discord.Interaction, account: Optional[str] = None):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		if not await self.backend.has_permission(interaction.user, bknd.Permissions.VIEW_BALANCE, account=acc):
			return await responder(f"You do not have permission to view the balance of {acc.account_name}", colour=discord.Colour.red())

		await responder(message=f'The balance on {acc.account_name} is: {acc.get_balance()}')

	@discord.app_commands.describe(
		amount="The amount to transfer, up to 2 decimal places",
		to_account="The account to transfer to",
		transaction_type="The type of the transaction, defaults to income"
	)
	@discord.app_commands.command(description="Transfer an amount to another account")
	async def transfer(self, interaction: discord.Interaction, amount: str, to_account: str, transaction_type: bknd.TransactionType = bknd.TransactionType.INCOME):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		from_acc = await self.bot.get_account(interaction.user.id, economy)
		if not from_acc:
			return await responder("Could not perform transaction: From account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		to_acc = await self.bot.get_account_by_name(to_account, economy)
		if not to_acc:
			return await responder("Could not perform transaction: To account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		try:
			await self.backend.perform_transaction(interaction.user, from_acc, to_acc, parse_amount(amount), transaction_type)
			await responder("Successfully performed transaction")
		except Exception as e:
			await responder(f"Could not perform transaction: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(
		amount="The amount to transfer, up to 2 decimal places",
		to_account="The account to transfer to",
		payment_interval="The frequency of the recurring transfer in days",
		number_of_payments="The number of payments to transfer, leave empty for infinite transfers",
		transaction_type="The type of the transaction, defaults to income"
	)
	@discord.app_commands.command(description="Creates a recurring transfer that begins from the next payment interval")
	async def create_recurring_transfer(self, interaction: discord.Interaction,
		amount: str, to_account: str,
		payment_interval: int,
		number_of_payments: Optional[int] = None,
		transaction_type: bknd.TransactionType = bknd.TransactionType.INCOME):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		from_acc = await self.bot.get_account(interaction.user.id, economy)
		if not from_acc:
			return await responder("From Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		to_acc = await self.bot.get_account_by_name(to_account, economy)
		if not to_acc:
			return await responder("To Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())
		elif payment_interval <= 0:
			return await responder("Payment interval has to be atleast one day", colour=discord.Colour.red())

		try:
			await self.backend.create_reccuring_transfer(
				interaction.user,
				from_acc,
				to_acc,
				parse_amount(amount),
				payment_interval,
				number_of_payments,
				transaction_type
			)
			await responder("Successfully created recurring transfer")
		except Exception as e:
			await responder(f"Could not create reccuring transfer: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(
		account="The account to view the transactions of, defaults to the current logged in account",
		limit="The amount of transactions to view, defaults to 10",
		as_csv="Whether to output transactions as a CSV file"
	)
	@discord.app_commands.command(description="View the transactions of an account")
	async def view_transaction_log(self, interaction: discord.Interaction, account: Optional[str] = None, limit: Optional[int] = 10, as_csv: bool = False):
		try:
			await self.backend.defer_with_ephemeral(interaction)
			edit = False

			responder = await self.backend.get_deferred_responder(interaction)
			economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
			if not economy:
				return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

			acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
			if not acc:
				return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

			if not as_csv:
				await responder("Loading...")
				edit = True

			try:
				transactions = await self.backend.get_transaction_log(interaction.user, acc, limit)
				if not transactions:
					return await responder("No transactions have been logged yet", edit=True)
			except Exception as e:
				return await responder(f"Could not fetch transaction log: {e}", colour=discord.Colour.red(), edit=edit)
				
			if as_csv:
				file = generate_transaction_csv(list(transactions), currency=economy.currency_unit, bot=self.bot)
				await responder(f"Logged latest `{len(transactions)}` transaction(s)", as_embed=False, file=file)
			else:
				
					items = [f"- {t.timestamp.strftime('%d/%m/%y %H:%M')} {t.target_account.get_name()} -- {bknd.frmt(t.amount)}{economy.currency_unit} → {t.destination_account.get_name()}"
							for t in transactions]

					chunks = PaginatorView.segment_by_length(items)
					if len(chunks) == 1:
						entries = '\n'.join(chunks[0])
						await responder(entries, edit=True)
					else:
						entries = []
						for chunk in chunks:
							entries.append(
								create_embed(
									interaction.command.name if interaction.command else "transactions",
									'\n'.join(chunk),
									discord.Colour.yellow(),
									with_footer=True)
							)

						view = PaginatorView(entries)
						msg = await responder(embed=view.embeds[0], view=view, wait=True, edit=edit)
						if msg:
							view.message = msg
		except Exception:
			traceback.print_exc()

	@discord.app_commands.describe(
		target="The user or role to view permissions of",
		account="The account to view permissions of, defaults to the current logged in account",
	)
	@discord.app_commands.command(description="View the permissions of a target on an account")
	async def view_permissions(self, interaction: discord.Interaction, target: discord.Member | discord.Role, account: Optional[str] = None):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1)
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		permissions = await self.backend.get_permissions(target, economy)
		names, allowed = [], []
		
		for permission in permissions:
			names.append(permission.permission.name)
			allowed.append(str(permission.allowed))

		embed = discord.Embed(
			description=f"## Permissions for account {acc.account_name}"
		) \
		.add_field(name="Permission", value='\n'.join(names)) \
		.add_field(name="Allowed", value='\n'.join(allowed))

		await responder(embed=embed)

	@discord.app_commands.describe(
		affects="The user or role to view permissions of",
		permission="The permission to update",
		state="Whether the permission is allowed, disallowed or reset to its default state",
		account="The account to update the permission for, defaults to the current logged in account",
		universal="Whether the permission applies to this economy or all economies"
	)
	@discord.app_commands.command(description="Update the state of a permission on a target for an account")
	async def update_permission(self, interaction: discord.Interaction,
		affects: discord.Member | discord.Role, permission: bknd.Permissions,
		state: PermissionState, account: Optional[str] = None, universal: bool = False):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		try:
			if state == PermissionState.DEFAULT:
				await self.backend.reset_permission(interaction.user, affects.id, permission, acc, economy if not universal else None)
			else:
				allowed = bool(state.value)
				await self.backend.change_permission(interaction.user, affects.id, permission, acc, economy if not universal else None, allowed)
			await responder("Successfully updated permission")
		except Exception as e:
			await responder(f"Could not update permission: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(
		to_account="The account to print funds to",
		amount="The amount to print, up to 2 decimal places",
		skip_confirmation="Whether to skip the confirmation view"
	)
	@discord.app_commands.command(description="Print funds to an account")
	async def print_funds(self, interaction: discord.Interaction, to_account: str, amount: str, skip_confirmation: bool = False):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(to_account, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.MANAGE_FUNDS, economy=economy):
			return await responder("Could not print funds: You do not have the permission to print funds", colour=discord.Colour.red())

		confirm = skip_confirmation
		
		if not skip_confirmation:
			confirm_view = ConfirmationView()
			await responder(f"Are you sure you want to print funds to this account?", view=confirm_view)
			await confirm_view.wait()
			confirm = confirm_view.confirmation
			
		if confirm:
			try:
				await self.backend.print_funds(interaction.user, acc, parse_amount(amount))
				await responder("Successfully printed funds", edit=True, view=None)
			except Exception as e:
				await responder(f"Could not print funds: {e}", colour=discord.Colour.red(), edit=True, view=None)
		else:
			await responder(f"Cancelled operation", edit=True, view=None)

	@discord.app_commands.describe(
		from_account="The account to remove funds from",
		amount="The amount to print, up to 2 decimal places",
		skip_confirmation="Whether to skip the confirmation view"
	)
	@discord.app_commands.command(description="Remove funds from an account")
	async def remove_funds(self, interaction: discord.Interaction, from_account: str, amount: str, skip_confirmation: bool = False):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(from_account, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.MANAGE_FUNDS, economy=economy):
			return await responder("Could not remove funds: You do not have the permission to remove funds", colour=discord.Colour.red())

		confirm = skip_confirmation

		if not skip_confirmation:
			confirm_view = ConfirmationView()
			await responder(f"Are you sure you want to remove funds from this account?", view=confirm_view)
			await confirm_view.wait()
			confirm = confirm_view.confirmation
			
		if confirm:
			try:
				await self.backend.remove_funds(interaction.user, acc, parse_amount(amount))
				await responder("Successfully removed funds", edit=True, view=None)
			except Exception as e:
				await responder(f"Could not remove funds: {e}", colour=discord.Colour.red(), edit=True, view=None)
		else:
			await responder(f"Cancelled operation", edit=True, view=None)

	@discord.app_commands.describe(
		tax_name="The name of the new tax bracket",
		affected_type="The account type affected by the tax bracket",
		tax_type="The type of tax to collect",
		bracket_start="The starting account balance of the tax bracket",
		bracket_end="The ending account balance of the tax bracket, leave empty for no end limit",
		rate="Percentage rate of the tax bracket",
		to_account="The account to send tax revenue to"
	)
	@discord.app_commands.command(description="Creates a new tax bracket")
	async def create_tax_bracket(self, interaction: discord.Interaction,
		tax_name: str, affected_type: bknd.AccountType, tax_type: bknd.TaxType,
		bracket_start: str, bracket_end: Optional[str], rate: int, to_account: str):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(to_account, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		try:
			await self.backend.create_tax_bracket(
				interaction.user,
				tax_name,
				affected_type,
				tax_type,
				parse_amount(bracket_start),
				parse_amount(bracket_end) if bracket_end else None,
				rate, acc
			)
			await responder("Successfully created tax bracket")
		except Exception as e:
			await responder(f"Could not create tax bracket: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(
		tax_name="The name of the new tax bracket",
		skip_confirmation="Whether to skip the confirmation view"
	)
	@discord.app_commands.command(description="Deletes a tax bracket")
	async def delete_tax_bracket(self, interaction: discord.Interaction, tax_name: str, skip_confirmation: bool = False):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.MANAGE_TAX_BRACKETS, economy=economy):
			return await responder("Could not delete tax bracket: You do not have the permission to manage tax brackets in this economy", colour=discord.Colour.red())

		confirm = skip_confirmation

		if not skip_confirmation:
			confirm_view = ConfirmationView()
			await responder(f"Are you sure you want to delete tax bracket `{tax_name}`?", view=confirm_view)
			await confirm_view.wait()
			confirm = confirm_view.confirmation
			
		if confirm:
			try:
				await self.backend.delete_tax_bracket(interaction.user, tax_name, economy)
				await responder("Successfully deleted tax bracket", edit=True, view=None)
			except Exception as e:
				await responder(f"Could not delete tax bracket: {e}", colour=discord.Colour.red(), edit=True, view=None)
		else:
			await responder(f"Cancelled operation", edit=True, view=None)

	@discord.app_commands.describe(skip_confirmation="Whether to skip the confirmation view")
	@discord.app_commands.command(description="Performs a tax cycle")
	async def perform_tax(self, interaction: discord.Interaction, skip_confirmation: bool = False):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())
		elif not await self.backend.has_permission(interaction.user, bknd.Permissions.MANAGE_TAX_BRACKETS, economy=economy):
			return await responder("Could not perform tax cycle: You do not have the permission to trigger taxes in this economy", colour=discord.Colour.red())

		confirm = skip_confirmation

		if not skip_confirmation:
			confirm_view = ConfirmationView()
			await responder(f"Are you sure you want to perform a tax cycle?", view=confirm_view)
			await confirm_view.wait()
			confirm = confirm_view.confirmation
			
		if confirm:
			try:
				await self.backend.perform_tax(interaction.user, economy)
				await responder("Successfully performed tax cycle", edit=True, view=None)
			except Exception as e:
				await responder(f"Could not perform tax cycle: {e}", colour=discord.Colour.red(), edit=True, view=None)
		else:
			await responder(f"Cancelled operation", edit=True, view=None)

	@discord.app_commands.command(description="Toggles the ephemeral state, which allows you to run commands in private (non-public embeds)")
	async def toggle_ephemeral(self, interaction: discord.Interaction):
		responder = await self.backend.get_responder(interaction)
		member = await self._get_member(interaction)
		if not member:
			return
		await self.backend.toggle_ephemeral(member)
		await responder("Successfully updated your preferences")

	@discord.app_commands.describe(account="The account to subscribe to, defaults to the current logged in account",)
	@discord.app_commands.command(description="Subscribes to an account's balance updates")
	async def subscribe(self, interaction: discord.Interaction, account: Optional[str]):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		try:
			await self.backend.subscribe(interaction.user, acc)
			await responder("Successfully subscribed to account")
		except Exception as e:
			await responder(f"Could not subscribe to account: {e}", colour=discord.Colour.red())

	@discord.app_commands.describe(account="The account to unsubscribe from, defaults to the current logged in account",)
	@discord.app_commands.command(description="Unsubscribes from an account's balance updates")
	async def unsubscribe(self, interaction: discord.Interaction, account: Optional[str]):
		responder = await self.backend.get_responder(interaction)
		economy = await self.backend.get_guild_economy(interaction.guild_id or -1) 
		if not economy:
			return await responder("This guild is not registered to an economy", colour=discord.Colour.red())

		acc = await self.bot.get_account_by_name(account, economy) if account else await self.bot.get_account(interaction.user.id, economy)
		if not acc:
			return await responder("Account not found, perhaps you need to create an account or check if the specified account exists?", colour=discord.Colour.red())

		try:
			await self.backend.unsubscribe(interaction.user, acc)
			await responder("Successfully unsubscribed from account")
		except Exception as e:
			await responder(f"Could not unsubscribe from account: {e}", colour=discord.Colour.red())

# Configuration
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

if __name__ == "__main__":
	config = load_config()
	db_path = config.get("database_uri", "sqlite+aiosqlite:///database.db")
	token: Optional[str] = config.get("discord_token")
	
	public_webhook_url, private_webhook_url = config.get("public_webhook_url"), config.get("private_webhook_url")

	async def main():
		if not token:
			logger.log(logging.CRITICAL, "Discord token not found in the config file")
			return sys.exit(1)

		if public_webhook_url:
			setup_webhook(backend_logger, public_webhook_url, bknd.LogLevels.Public)
	   
		if private_webhook_url:
			setup_webhook(backend_logger, private_webhook_url, bknd.LogLevels.Private)

		async with Taubot(intents=intents, command_prefix="!", help_command=None) as bot:
			async with DiscordBackendInterface(bot, db_path, **config.get("engine_options", {}), poolclass=AsyncAdaptedQueuePool) as _backend:
				bot.backend = _backend
				await bot.start(token)

	try:
		asyncio.run(main())
	except (KeyboardInterrupt, asyncio.CancelledError):
		pass