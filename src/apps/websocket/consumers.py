from channels.generic.websocket import AsyncWebsocketConsumer
import json

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope["user"]

        if user.is_anonymous:
            await self.close()
        else:
            self.room_name = self.scope['url_route']['kwargs']['room_name']
            self.group_name = f"chat_{self.room_name}"

            await self.channel_layer.group_add(
                self.group_name, self.channel_name
            )
            await self.accept()

    async def disconnect(self, code):
        if hasattr(self, 'group_name'):  # ✅ check before discard
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    async def receive(self, text_data=None, bytes_data=None):
        user = self.scope["user"]
        data = json.loads(text_data)
        message = data['message']

        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'chat_message',
                'message': message,
                'username': user.username if user.is_authenticated else "Anonymous"
            }
        )

    async def chat_message(self, event):
        message = event['message']
        username = event['username']

        await self.send(text_data=json.dumps({
            'username': username,
            'message': message
        }))
