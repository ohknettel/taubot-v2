import sys
import json
import csv
import io
import uuid
import discord
import re
import traceback
from backend import frmt

USER_MENTION_REGEX = re.compile(r"<@!?([0-9]*)>")

def load_config():
    if len(sys.argv) > 3:
        print("Usage: main.py config_path")
        sys.exit(1)

    path = "config.json" if len(sys.argv) < 2 else sys.argv[1]
    try:
        with open(path) as file:
            return json.load(file)
    except:
        return {}

def resolve_mentions(name: str, bot: discord.Client) -> str:
    """
    Helper function to resolve mentions in account names where applicable.
    
    :param name: The account name.
    
    :returns: The accout name with mentions resolved.
    """

    name = name.strip()
    for match in re.finditer(USER_MENTION_REGEX, name):
        try:
            if len(match.string) <= 0:
                continue

            _id = int(match.group(1))
            user = bot.get_user(_id)

            if user:
                name = re.sub(re.escape(match.group(0)), user.name, name)
        except Exception:
            traceback.print_exc()
            continue

    return name

def generate_transaction_csv(transactions: list, filename: str | None = None, *, currency: str, as_discord_file = True, bot: discord.Client | None = None):
    """
    Generates a CSV file from a list of transactions.
    
    :param transactions: The list of transactions.
    :param filename: The filename to save the CSV file as.
    :param currency: The general currency of the transactions' economy.
    :param as_discord_file: Whether to return the CSV as a Discord file.
    :param bot: A Discord client that will be used to resolve mentions.
    
    :returns: The bytestream of the CSV file if `as_discord_file` is disabled, else returns Discord attachment of the CSV file. 
    """

    filename = filename or (str(uuid.uuid4()) + '.csv')
    with io.StringIO() as buffer:
        writer = csv.writer(buffer)
        writer.writerow(["Timestamp", "From", f"Amount ({currency})", "To"]) # header
        account_name_fmt = lambda acc: resolve_mentions(acc.get_name(), bot) if bot else acc.get_name()

        if len(transactions) > 0:
            writer.writerows(
                [
                    t.timestamp.strftime("%d/%m/%y %H:%M"),
                    account_name_fmt(t.target_account),
                    frmt(t.amount),
                    account_name_fmt(t.destination_account)
                ] for t in transactions
            )

        buffer.seek(0)
        byte = io.BytesIO(buffer.getvalue().encode("utf-8"))
    
    if as_discord_file:
        return discord.File(byte, filename=filename)
    else:
        return byte