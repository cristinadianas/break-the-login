import os
from app import create_app


app = create_app()


if __name__ == "__main__":
    https = os.environ.get("AUTHX_HTTPS", "true").lower() != "false"
    kwargs = dict(host="0.0.0.0", port=5000, debug=False)
    if https:
        kwargs["ssl_context"] = "adhoc"   # cere pyopenssl
        print("Pornire AuthX v2 pe https://0.0.0.0:5000  (cert self-signed)")
        print("  pentru curl:  curl -k https://192.168.95.128:5000/...")
    else:
        print("Pornire AuthX v2 pe http://0.0.0.0:5000  (HTTP — Secure flag inactiv)")
    app.run(**kwargs)

