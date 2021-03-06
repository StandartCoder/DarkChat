import json
from dataclasses import dataclass
from dataclasses_json import dataclass_json

from streaming import createMsg

@dataclass_json
@dataclass
class Message:
    shost: str
    dhost: str
    username: str
    date: str
    cont: str
    typ: str
    shouldParseContents: bool = False

    if shouldParseContents:
        if type(cont) == str:
            cont = json.loads(cont)
        else:
            cont = json.dumps(cont)

    def pack(self):
        return createMsg(self.to_json())
