API
===

.. _API application form: https://forms.gle/hs1B1GZ9rFcCjSUi9

Taubot V2.1 exposes an HTTPS API available at https://taubot.qzz.io/api, refered to in this documentation from here on out as TBAPI. The main usage of TBAPI is to enable applications and businesses to automate different aspects of Taubot such as transferring funds from one account to another.

Authentication
--------------

Please fill out the `API application form`_ to request an application be made and a key to be provided.

TBAPI relies on two kinds of API keys: **Master** and **Grant**.

.. _keys:

.. list-table::
   :widths: 50 50
   :header-rows: 1
   
   * - Master Key
     - Grant Key
   * - Master keys are issued to applications and are notable for their ability to create **Grant** keys.
     - Grant keys are issued to individuals by the Department of Technology in order to enable them to control their personal accounts. Primarily, they are issued by users to applications to grant the application a subset of permissions on a certain account.

The key being used to make a request should be set as the :code:`Authorization` HTTP header, for example:

.. code-block:: text

   Authorization: Bearer YOUR_KEY_HERE

.. warning::

   **Master keys expire in 60 days, while Grant keys expire in 90 days.**

App authorization flow overview
-------------------------------

This section pertains to the creation of **Grant** keys by users for applications.

This process ensures that users maintain full control over their spending limits while providing the application with a key to control their account.

The gist of the process is as follows:
    1. Application posts to the :http:post:`/api/references/register` endpoint, using a **Master** key with a query parameter of the permissions they wish to get, and receives a UUID.

    2. Application gives the user a manufactured grant link using the UUID from the response.

    3. User visits the grant link and authenticates with Discord.

    4. User sets their preferred spending limit and authorizes the application.

    5. User returns to application and confirms that they've completed the authorization process.

    6. Application retrieves their **Grant** key from :http:get:`/api/references/{ref_id}`, where :code:`ref_id` is the UUID from the application's response in step 1.

.. warning::

   **The application has up to an hour from the completion of the first step to complete this process.**

More detailed explanations for the major parts of the process are provided below.

Permissions
^^^^^^^^^^^

TBAPI uses bitmasks to bundle multiple permissions into a single integer, similar to Discord's authentication system for adding bots to servers.

TBAPI currently allows applications to request the following permissions. These permissions are the same as :ref:`the permissions defined in the backend <permissions_bk>`. We may update this list in the future to allow applications to request more of Taubot's permissions in accordance with demand, technical capabilities and security.

.. list-table::
   :widths: 20 10 70
   :header-rows: 1

   * - Constant
     - Value
     - Description
   * - :code:`VIEW_BALANCE`
     - **1**
     - Allows the application to view an account's balance.
   * - :code:`TRANSFER_FUNDS`
     - **3**
     - Allows the application to transfer funds from an account.

For example, if an application wishes to request both :code:`VIEW_BALANCE` and :code:`TRANSFER_FUNDS`, the resulting bitmask will be **10**.

.. code-block:: python

   >>> (1 << 1) | (1 << 3)
   10

Receiving a reference UUID
^^^^^^^^^^^^^^^^^^^^^^^^^^

As mentioned in the gist, the application must send a request to :http:post:`/api/references/register` endpoint through a **Master** key with a query parameter of the permissions they wish to get.

Endpoints
"""""""""

.. http:post:: /api/references/register

   .. note::

      This endpoint is limited to :ref:`Master keys <keys>` only.

   Registers a create reference from a **Master** key.

   :query permissions: The required permissions integer bitmask.

   :>json uuid: A unique reference UUID.

   :status 200: Returns a reference UUID.
   :status 400: Permissions bitmask is empty or malformed.
   :status 403: Request was made with a **Grant** key instead of the original **Master** key.

   **Example Response (200 OK)**

   .. code-block:: json

      {
        "uuid": "331fa966-33e4-4513-82ee-890f97e3f6ec"
      }

Constructing a grant URL
^^^^^^^^^^^^^^^^^^^^^^^^

After receiving the reference UUID from the TBAPI, the application must construct a grant URL in the format :code:`/api/oauth/grant?ref_id={ref_id}&app_id={app_id}`, where :code:`ref_id` is the reference UUID it received and :code:`app_id` is the application's own ID, and give it to the user.

Using the UUID from the above example response, this may look like:

.. code-block:: text

   https://taubot.qzz.io/api/oauth/grant?ref_id=331fa966-33e4-4513-82ee-890f97e3f6ec&app_id=02d60c91-3362-4dc5-8c55-0a69e8f35ed6

Authorization on the user's end
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once the user visits this grant URL, they will be redirected to Discord's authentication page, and then to TBAPI's grant page, where they are shown the permissions the application is requesting and are allowed to set a spending limit or disable the spending limit.

.. figure:: _static/media/discord_oauth.png
   
   Discord authenatication page

.. figure:: _static/media/grant_unchecked.png
   
   TBAPI grant page

.. figure:: _static/media/grant_checked.png
   
   Spending limit warning when disabled

.. figure:: _static/media/authorized.png
   
   Authorization confirmation

Retrieving the grant key
^^^^^^^^^^^^^^^^^^^^^^^^

After the user has informed the application that they've authorized the application, the application must retrieve their **Grant** key by sending a request to :http:get:`/api/references/{ref_id}` with :code:`ref_id` replaced with the reference UUID the application received earlier.

Endpoints
"""""""""

.. http:get:: /api/references/{ref_id}

   Retrieves a reference's **Grant** key. This request must be sent by the original **Master** key in case of registering the reference through :http:post:`/api/references/register`, or the pre-existing grant key in case of registering the reference through :http:patch:`/api/references/register`.

   :path ref_id: The reference UUID supplied by TBAPI.

   :status 200: Returns a **Grant** key.
   :status 400: The reference UUID is invalid or malformed.
   :status 403: The user has not yet authorized the application, or the request is made using the wrong type of key.
   :status 404: The reference was not found.

   **Example Response (200 OK)**

   .. code-block:: json

      {
        "key": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9..."
      }

Updating the grant key
^^^^^^^^^^^^^^^^^^^^^^

In case your application's grant key has reached the spending limit, or you need access to more permissions than initally authorized, you can send a :http:patch:`/api/references/register` request instead of creating a new grant key. At the end of the update process (which is the exact same as the authorization process), you will receive a new grant key, **and the old grant key will be invalidated**.

Endpoints
"""""""""

.. http:patch:: /api/references/register

   .. note::

      This endpoint is limited to :ref:`Grant keys <keys>` only.

   Registers a update reference from a **Grant** key.

   :query permissions: **(Optional)** The required permissions integer bitmask.

   :>json uuid: A unique reference UUID.

   :status 200: Returns a reference UUID.
   :status 400: Permissions bitmask is malformed.
   :status 403: Request was made with a **Master** key instead of the pre-existing **Grant** key.

   **Example Response (200 OK)**

   .. code-block:: json

      {
        "uuid": "5d92d48b-372f-4dd2-ac7d-01e87da5e4e6c"
      }

API reference
-------------

Response Types
^^^^^^^^^^^^^^

.. _application:

Application
"""""""""""

.. list-table::
   :widths: 20 20 50
   :header-rows: 1
   :stub-columns: 1

   * - Key
     - Type
     - Description
   * - application_id
     - String
     - The application's UUID, encoded as a string
   * - application_name
     - String
     - The name of the application
   * - economy_name
     - String
     - The application's economy currency name
   * - economy_id
     - String
     - The application economy's UUID, encoded as a string
   * - owner_id
     - String
     - The application owner's ID, encoded as a string

.. _account:

Account
"""""""

.. list-table::
   :widths: 20 20 50
   :header-rows: 1
   :stub-columns: 1

   * - Key
     - Type
     - Description
   * - account_id
     - String
     - The account's UUID, encoded as a string
   * - owner_id
     - String
     - The account owner's ID, encoded as a string
   * - account_name
     - String
     - The name of the account
   * - account_type
     - String
     - The type of account
   * - balance
     - Integer
     - The balance of the account in cents (for example: 100 would be 1 of a currency and 101 would be 1.01 of a currency)

.. _transaction:

Transaction
"""""""""""

.. list-table::
   :widths: 20 20 50
   :header-rows: 1
   :stub-columns: 1

   * - Key
     - Type
     - Description
   * - actor_id
     - String
     - The ID of the user or API key that performed this transaction, encoded as a string
   * - timestamp
     - Double
     - The Unix timestamp of when the transaction took place, returned as a float
   * - from_account
     - String
     - The account UUID of the account the money was transferred from, encoded as a string
   * - to_account
     - String
     - The account UUID of the account the money was sent to, encoded as a string
   * - amount
     - Integer
     - The amount in cents that was transferred

Endpoints
^^^^^^^^^

.. http:get:: /api/applications/{app_id}

   Gets an application by its UUID.

   :path app_id: The application's UUID or :code:`me` for the requesting key's application.

   :status 200: Returns an :ref:`Application <application>` object.
   :status 400: Application UUID is invalid or malformed.
   :status 404: Application not found.

   **Example Response (200 OK)**

   .. code-block:: json

      {
        "application_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "application_name": "test",
        "economy_name": "test",
        "economy_id": "af93101b-8301-4f97-96b5-dcfa9a28f90a",
        "owner_id": "809875420350119958"
      }

.. http:get:: /api/applications/users/{user_id}

   Gets a user's applications.

   :path user_id: The user's Discord ID.

   :status 200: Returns a list of :ref:`Application <application>` objects.
   :status 400: User ID is a non-integer value.
   :status 403: The requesting key does not have the permission to view user applications (:code:`MANAGE_ECONOMIES`).

   **Example Response (200 OK)**

   .. code-block:: json

      [
        {
           "application_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
           "application_name": "test",
           "economy_name": "test",
           "economy_id": "af93101b-8301-4f97-96b5-dcfa9a28f90a",
           "owner_id": "809875420350119958"
        }
      ]

.. http:get:: /api/accounts

   Gets an account matching a specific name or owned by a specific user. **Only one query parameter must be provided.**

   :query user_id: The user's Discord ID.
   :query name: The account's name.

   :status 200: Returns an :ref:`Account <account>` object.
   :status 400: Both or neither of :code:`user_id` and :`name` were entered, or the user ID is a non-integer value.
   :status 404: Account not found.

   **Example Request (HTTP)**

   .. code-block:: http

      GET /api/accounts?user_id=809875420350119958 HTTP/1.1
      Host: taubot.qzz.io
      Authorization: Bearer ...

   .. note ::

      The requesting key must have the :code:`VIEW_BALANCE` permission to get the account's balance, else the balance returned will be :code:`null`.

   **Example Response (200 OK)**

   .. code-block:: json

      {
        "account_id": "021b1643-fcec-4cbb-bc00-ea136155e2e8",
        "owner_id": "809875420350119958",
        "account_name": "<@!809875420350119958>'s account",
        "account_type": "USER",
        "balance": null
      }

.. http:get:: /api/accounts/{acc_id}

   Gets an account by its UUID.

   :path acc_id: The account's UUID.

   :status 200: Returns an :ref:`Account <account>` object.
   :status 400: Account UUID is invalid or malformed.
   :status 404: Account not found.

   .. note::

      The requesting key must have the :code:`VIEW_BALANCE` permission to get the account's balance, else the balance returned will be :code:`null`.

   **Example Response (200 OK)**

   .. code-block:: json

      {
        "account_id": "021b1643-fcec-4cbb-bc00-ea136155e2e8",
        "owner_id": "809875420350119958",
        "account_name": "<@!809875420350119958>'s account",
        "account_type": "USER",
        "balance": null
      }

.. http:post:: /api/transactions/create

   .. note ::

      This endpoint is limited to :ref:`Grant keys <keys>` only.

   Creates a new transaction; i.e. transfers fund from the requesting key's account to another account.

   :json to_account_id: The UUID of the destination account.
   :json amount: The amount to transfer in cents.

   :status 200: Transaction is successful.
   :status 400: To account UUID is invalid or malformed.
   :status 403: **Error code 1000** - Cannot transfer from and to the same account.
   :status 403: **Error code 1001** - Insufficient funds.
   :status 403: **Error code 1002** - Spending limit reached.
   :status 404: To account not found.

   **Example Request Body**

   .. code-block:: json

      {
        "to_account_id": "021b1643-fcec-4cbb-bc00-ea136155e2e8",
        "amount": 10000
      }

   **Example Response (403 Forbidden)**

   .. code-block:: json

      {
        "error_code": 1000,
        "detail": "Cannot transfer from and to the same account"
      }

   **Example Response (200 OK)**

   .. code-block:: json

      {
        "detail": "Successfully performed transaction"
      }

.. http:get:: /api/transactions

   .. note ::

      This endpoint is limited to :ref:`Grant keys <keys>` only.

   Get the transactions of the requesting key's account.

   :query limit: **(Optional)** The amount of transactions to return. Must be greater than 0 and less than 100.
   :query sort: **(Optional)** Whether to sort the transactions in ascending or descending order of date. :code:`0` - newest first, :code:`1` - oldest first.
   :query before: **(Optional)** Filter transactions made before a float timestamp.
   :query after: **(Optional)** Filter transactions made after a float timestamp.
   
   :status 200: Returns a list of :ref:`Transaction <transaction>` objects.
   :status 400: **Error code 2000** - Invalid sort mode.
   :status 400: **Error code 2001** - Limit is less than or equal to 0.
   :status 400: **Error code 2002** - Limit is greater than 100.
   :status 403: The requesting key does not have the permission to view transactions (:code:`VIEW_BALANCE`).

   **Example Request (HTTP)**

   .. code-block:: http

      GET /api/transactions?limit=10&sort=1 HTTP/1.1
      Host: taubot.qzz.io
      Authorization: Bearer ...

   **Example Response (403 Forbidden)**

   .. code-block:: json

      {
        "error_code": 2000,
        "detail": "Sort mode must be either: 0 - newest first, 1 - oldest first"
      }

   **Example Response (200 OK)**

   .. code-block:: json

      [
        {
          "actor_id": "2",
          "timestamp": 1770647320.966851,
          "from_account": "021b1643-fcec-4cbb-bc00-ea136155e2e8",
          "to_account": "d107dd80-54de-4537-bd0c-fb63b9b0aff6",
          "amount": 300
        },
        {
          "actor_id": "3",
          "timestamp": 1770632032.316085,
          "from_account": "021b1643-fcec-4cbb-bc00-ea136155e2e8",
          "to_account": "d107dd80-54de-4537-bd0c-fb63b9b0aff6",
          "amount": 30000
        }
      ]