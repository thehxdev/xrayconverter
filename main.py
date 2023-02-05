from fastapi import FastAPI
from vpn.inbounds import Inbounds


app = FastAPI()


@app.get("/xray/info")
async def all_inbounds_info(verbose: bool = False):
    i = Inbounds()
    return i.all_inbounds_index_and_info(verbose)


@app.get("/xray/inbounds/users")
async def inbound_users(
        index: int = 0
        ):
    i = Inbounds(inbound_index=index)
    users_with_emails = zip(i.inbound_users_email(), i.inbound_users())

    users = {email:user_id for email, user_id in users_with_emails}
    return users


@app.post("/xray/users/add")
async def add_user_to_xray(
        username:str
        ):
    i = Inbounds(inbound_index=0)

    if username in i.inbound_users_email():
        return {"status": "error", "msg": "user already exists"}

    added_user = i.add_user_to_inbound(username)
    try:
        i.write_changes_to_xray_config()
    except:
        return {"status": "error", "msg": f"error while writing changes to {i.xray_config}"}
    return {"status": "ok", "user": added_user}

