import json
from channels.generic.websocket import AsyncWebsocketConsumer

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)

        # Distinguish between chat messages and signaling messages
        if 'message' in data:
            # Normal chat message
            message = data['message']
            username = data.get('username', 'Anonymous')

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message,
                    'username': username
                }
            )
        else:
            # Signaling messages for WebRTC 
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'signaling_message',
                    'data': data,
                    'sender_channel_name': self.channel_name # Pass sender's ID
                }
            )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'username': event['username'],
            'message': event['message']
        }))

    async def signaling_message(self, event):
        # Only forward the signal if the current consumer is NOT the sender.
        if event['sender_channel_name'] != self.channel_name:
            # Structure the data under a 'signal' key for client-side parsing
            await self.send(text_data=json.dumps({
                'signal': event['data']
            }))