import json
from channels.generic.websocket import AsyncWebsocketConsumer


class ModuleRunConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        run_id = self.scope['url_route']['kwargs']['run_id']
        self.group = f'run_{run_id.replace("-", "_")}'
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            msg = json.loads(text_data)
        except ValueError:
            return
        if msg.get('type') == 'kill':
            from . import runner
            run_id = self.scope['url_route']['kwargs']['run_id']
            runner.kill_proc(run_id, int(msg['proc_index']))

    async def run_output(self, event):
        await self.send(text_data=json.dumps(event['message']))
