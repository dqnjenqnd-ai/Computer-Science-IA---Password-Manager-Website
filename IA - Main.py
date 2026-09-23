from website import create_app

app = create_app()

if __name__ == '__main__': # only when I run this file, not import file --> execute line 6
    # app.run(host='0.0.0.0', port=5000, debug=False) # run Flask application
    app.run(debug=True)

"""
host='0.0.0.0'
makes the app reachable from other devices on the same Wi-Fi (phone, tablet, other laptop)
On the phone, open  http://<laptop-IP>:5000
On macOS the laptop IP can be found with:  ipconfig getifaddr en0
"""

"""
debug=False
debug mode + host 0.0.0.0 would expose Flask's interactive debugger to everyone on the network

For development on your own laptop only, temporarily use: app.run(debug=True)
"""
