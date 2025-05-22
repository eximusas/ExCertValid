'''
validate_tomcat.py

Script para validar:
 1. Existencia y configuración de Tomcat (paths).
 2. JAVA_HOME correcta y localización de cacerts.
 3. Keystore de Tomcat y presencia de alias/certificado.
 4. Conexión SSL a un dominio remoto usando el truststore de Java.

Requisitos:
 pip install pyjks cryptography
 Empaquetar con PyInstaller:
   pyinstaller --onefile validate_tomcat.py --name validate_tomcat
'''  
import os
import sys
import ssl
import socket
import argparse
import tempfile

try:
    import jks
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Faltan dependencias: pip install pyjks cryptography")
    sys.exit(1)


def check_path(path, desc):
    if not os.path.exists(path):
        print(f"ERROR: No existe {desc}: {path}")
        return False
    print(f"OK: {desc} existe: {path}")
    return True


def find_cacerts(jdk_home):
    candidates = [
        os.path.join(jdk_home, 'lib', 'security', 'jssecacerts'),
        os.path.join(jdk_home, 'lib', 'security', 'cacerts'),
        os.path.join(jdk_home, 'jre', 'lib', 'security', 'jssecacerts'),
        os.path.join(jdk_home, 'jre', 'lib', 'security', 'cacerts'),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def extract_truststore(cacerts_path, password):
    # Carga JKS truststore y exporta todos los certificados a un PEM temporal
    ks = jks.KeyStore.loads(open(cacerts_path, 'rb').read(), password)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
    for alias, entry in ks.certs.items():
        cert = x509.load_der_x509_certificate(entry.cert, default_backend())
        tmp.write(cert.public_bytes(Encoding.PEM))
    tmp.close()
    return tmp.name


def test_ssl_connection(host, port, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                peer = ssock.getpeercert()
                print(f"SSL HANDSHAKE OK con {host}:{port}")
                print(f"Certificado recibido:\n  Subject: {peer.get('subject')}")
        return True
    except Exception as e:
        print(f"ERROR SSL handshake con {host}:{port}: {e}")
        return False


def inspect_keystore(ks_path, password):
    # Determina tipo JKS o PKCS12
    try:
        ks = jks.KeyStore.loads(open(ks_path, 'rb').read(), password)
    except jks.util.DecryptionFailureException:
        ks = jks.PKCS12KeyStore.loads(open(ks_path, 'rb').read(), password)
    print(f"Aliases en keystore {ks_path}:")
    for alias in ks.aliases:
        print(f"  - {alias}")
    return bool(ks.aliases)


def main():
    parser = argparse.ArgumentParser(description="Valida Tomcat/JDK SSL setup")
    parser.add_argument('--tomcat',   required=True, help='Directorio CATALINA_HOME')
    parser.add_argument('--jdk',      required=True, help='Directorio JAVA_HOME')
    parser.add_argument('--keystore', help='Ruta a servidor keystore (JKS/PKCS12)')
    parser.add_argument('--storepass', default='changeit', help='Password de truststore/keystore')
    parser.add_argument('--host',     help='Host remoto a probar SSL')
    parser.add_argument('--port',     type=int, default=443, help='Puerto remoto SSL')
    args = parser.parse_args()

    # 1) Validar paths
    check_path(args.tomcat, 'Tomcat Home')
    check_path(args.jdk,    'Java Home')

    # 2) Encontrar cacerts
    cacerts = find_cacerts(args.jdk)
    if not cacerts:
        print("ERROR: No se encontró cacerts/jssecacerts en JAVA_HOME.")
        sys.exit(1)
    print(f"Usando truststore: {cacerts}")

    # 3) Inspeccionar keystore de Tomcat si se pasa
    if args.keystore:
        if check_path(args.keystore, 'Keystore Tomcat'):
            if not inspect_keystore(args.keystore, args.storepass):
                print("ERROR: Keystore no contiene alias válidos.")
                sys.exit(1)

    # 4) Probar SSL remoto
    if args.host:
        pem = extract_truststore(cacerts, args.storepass)
        test_ssl_connection(args.host, args.port, cafile=pem)
        os.unlink(pem)

if __name__ == '__main__':
    main()
