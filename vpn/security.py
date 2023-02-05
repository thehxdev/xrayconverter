import uuid
import string
import random

class Security:

    def __init__(
            self,
            strong: bool = False
            ):
        self.chars = string.ascii_letters + string.digits
        if strong:
            self.chars = self.chars + "/~@$&!*#?"

    def genPass(self, passLength:int = 18):
        return "".join([random.choice(self.chars) for _ in range(passLength)])

    def genUUID1(self):
        return str(uuid.uuid1())

    def genUUID4(self):
        return str(uuid.uuid4())

