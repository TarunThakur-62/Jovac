def extract_qr_url(path):
 from PIL import Image
 from pyzbar.pyzbar import decode
 data=decode(Image.open(path))
 if not data:raise ValueError("No QR code detected")
 return data[0].data.decode()
