Usage
=====

.. _prerequisites:

Prerequisites
-------------

There are some programs that are needed to install Taubot, namely:

* Git
* Python 3.12+

For deployment of a production server it's recommended you install Postgres, but any SQL database should work although only Postgres and SQLite are supported, **using another DBMs may result in undefined behaviour**.

SQLite is recommended for local development environments as its setup and overhead are significantly less invasive.

.. _installation:

Installation
------------

First clone the repo and enter it:

.. code-block:: console 

   $ git clone https://github.com/ohknettel/taubot-v2.git && cd taubot-v2


Next, you should create a virtual environment to store all of the projects dependencies and activate it:

.. code-block:: console

   $ python3 -m venv .venv && .venv/bin/activate

Now it's time for you to install the dependencies:

.. code-block:: console

   $ python3 -m pip install -U -r requirements.txt

Once you've this done you should create your `config.json`, a redacted version of the one used in production is provided for your convenience:

.. code-block:: json

    {
        "discord_token": "Your bot token here",
        "database_uri": "postgresql+asyncpg://username:password@localhost/taubot",
        "private_webhook_url": "Webhook URL for all transaction logs to be sent too",
        "public_webhook_url": "Webhook URL for transactions by government officials to be sent too",
        "api": true,
        "sync": false,
        "oauth": {
                "redirect_url": "https://discord.com/oauth2/authorize?client_id=1236137854128623677&response_type=code&redirect_uri=https%3A%2F%2Ftaubot.qzz.io%2Fapi%2Foauth%2Foauth-callback&scope=identify",
                "redirect_uri": "https://taubot.qzz.io/api/oauth/oauth-callback",
                "client_id": "1236137854128623677",
                "client_secret": "Your oauth secret here"
        },
        "static_uri": "https://taubot.qzz.io/static",
        "session_key": "A secret key to encrypt sessions for user authorizing"
    }

Now your ready to go you can start Taubot with ``sync`` set to ``true`` to sync the commands with Discord. This flag should only be used after Taubot is newly installed or if it has had new commands added.

If you wish to run Taubot in the background you can run:

.. code-block:: console
   
    $ python3 src/main.py &>>./out.log &