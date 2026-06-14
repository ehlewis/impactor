
class EventBus:
    def __init__(self):
        self.handlers={}

    def subscribe(self,event,handler):
        self.handlers.setdefault(event,[]).append(handler)

    def publish(self,event,payload=None):
        for h in self.handlers.get(event,[]):
            h(payload)
