import socket
import tqdm
import os


SEPARATOR = '<SEPARATOR>'

BUFFER_SIZE = 4096  # send 4096 bytes each time step

host = '192.168.29.210'

port = 5001

file_name = 'demo.txt'

file_size = os.path.getsize(file_name)


s = socket.socket()

print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected.")

# send the file_name and file_size
s.send(f"{file_name}{SEPARATOR}{file_size}".encode())


# start sending the file
progress = tqdm.tqdm(range(
    file_size), f"Sending {file_name}", unit="B", unit_scale=True, unit_divisor=1024)
with open(file_name, "rb") as f:
    for _ in progress:
        # read the bytes from the file
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            # file transmitting is done
            break
        # we use sendall to assure transimission in
        # busy networks
        s.sendall(bytes_read)
        # update the progress bar
        progress.update(len(bytes_read))
# close the socket
s.close()
