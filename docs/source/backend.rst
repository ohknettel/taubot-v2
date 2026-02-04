Backend
=======

The backend infrastructure is designed for performant and simple usage. It is the **recommended** method for access and control over objects including, but not limited to:

* Economies
* Accounts
* Applications and API keys
* Tax brackets
* Recurring transfers

Classes
-------

Utility classes
^^^^^^^^^^^^^^^

.. autoclass:: backend.HasID

.. autoclass:: backend.HasRoles

.. autoclass:: backend.StubUser

Models
^^^^^^

.. autoclass:: backend.Economy
    :members:
    :undoc-members:

.. autoclass:: backend.Guild
    :members:
    :undoc-members:

.. autoclass:: backend.Application
    :members:
    :undoc-members:

.. autoclass:: backend.APIKey
    :members:
    :undoc-members:

.. autoclass:: backend.Account
    :members:
    :undoc-members:

.. autoclass:: backend.Transaction
    :members:
    :undoc-members:

.. autoclass:: backend.BalanceUpdateNotifier
    :members:
    :undoc-members:

.. autoclass:: backend.Permission
    :members:
    :undoc-members:

.. autoclass:: backend.Tax
    :members:
    :undoc-members:

.. autoclass:: backend.RecurringTransfer
    :members:
    :undoc-members:

Backend
^^^^^^^

.. autoclass:: backend.Backend
    :members:
    :undoc-members:

Enums
-----

.. autoclass:: backend.LogLevels
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: backend.AccountType
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: backend.Permissions
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: backend.TaxType
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: backend.TransactionType
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: backend.Actions
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: backend.CUD
    :members:
    :undoc-members:
    :member-order: bysource

.. autoclass:: backend.KeyType
    :members:
    :undoc-members:
    :member-order: bysource

Exceptions
----------

.. autoclass:: backend.BackendException

.. autoclass:: backend.UnauthorizedException

.. autoclass:: backend.NotFoundException

.. autoclass:: backend.AlreadyExistsException

.. autoclass:: backend.ValueError