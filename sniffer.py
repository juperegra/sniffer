import socket

# the public network interface
HOST = socket.gethostbyname(socket.gethostname())
HOST='10.188.250.172'

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


def ICMPFunc(DatosIP):
    Tipo = DatosIP[0]
    print('Tipo = ', Tipo)
    print("")

    Codigo = DatosIP[1]
    print("Codigo = ", Codigo)
    print("")

    ChecksumICMP=(DatosIP[3]<<8) | DatosIP[4]
    print("Checksum ICMP = ", hex(ChecksumICMP))
    print("")


def UDPFunc(DatosIP):
    PuertoOrigen = (DatosIP[0]<<8) | DatosIP[1]
    print("Puerto Origen = ", PuertoOrigen)
    print("")

    PuertoDestino = (DatosIP[2]<<8) | DatosIP[3]
    print("Puerto Destino = ", PuertoDestino)
    print("")

    Longitud = (DatosIP[4]<<8) | DatosIP[5]
    print("Longitud = ", Longitud)
    print("")

    ChecksumUDP = (DatosIP[6]<<8) | DatosIP[7]
    print("Checksum UDP= ", hex(ChecksumUDP))
    print("")

    DatosUDP = DatosIP[8:]

    DNSFunc(DatosUDP)


def TCPFunc(DatosIP):
    PuertoOrigen = (DatosIP[0]<<8) | DatosIP[1]
    print("Puerto Origen = ", PuertoOrigen)
    print("")

    PuertoDestino = (DatosIP[2]<<8) | DatosIP[3]
    print("Puerto Destino = ", PuertoDestino)
    print("")

    NumeroSecuencia = (((DatosIP[4]<<8) | DatosIP[5]) << 16) | ((DatosIP[6]<<8) | DatosIP[7])
    print("Numero de secuencia = ", NumeroSecuencia)
    print("")

    NumeroAsentimiento = ((((DatosIP[8]<<8) | DatosIP[9])<< 16) | ((DatosIP[10]<<8) | DatosIP[11]))
    print("Numero de asentimiento = ", NumeroAsentimiento)
    print("")

    LongitudCabecera = DatosIP[12]
    print("Longitud de la cabecera = ", LongitudCabecera)
    print("")

    URG = (DatosIP[13] & 0x020) >> 5
    ACK = (DatosIP[13] & 0x010) >> 4
    PSH = (DatosIP[13] & 0x008) >> 3
    RST = (DatosIP[13] & 0x004) >> 2
    SYN = (DatosIP[13] & 0x002) >> 1
    FIN = (DatosIP[13] & 0x001)

    if(URG == 1):
        print("Flag = URG")
        print("")

    if(ACK == 1):
        print("Flag = ACK")
        print("")

    if(PSH == 1):
        print("Flag = PSH")
        print("")

    if(RST == 1):
        print("Flag = RST")
        print("")

    if(SYN == 1):
        print("Flag = SYN")
        print("")

    if(FIN == 1):
        print("Flag = FIN")
        print("")

    VentanaAnunciada = (DatosIP[14]<<8) | DatosIP[15]
    print("Ventana anunciada = ", VentanaAnunciada)
    print("")

    ChecksumSegmento = (DatosIP[16]<<8) | DatosIP[17]
    print("Checksum segmento = ", hex(ChecksumSegmento))
    print("")

    Puntero = (DatosIP[18]<<8) | DatosIP[19]
    print("Puntero a datos urgentes = ", hex(Puntero))
    print("")


def DNSFunc(DatosUDP):

    Id = (DatosUDP[0] << 8) | DatosUDP[1]
    print("Id = ", hex(Id))
    print("")


    Flag = (DatosUDP[2] << 8) | DatosUDP[3]

    Opcode = (Flag & 0x800) >> 11
    TC = (Flag & 0x200) >> 9
    RD = (Flag & 0x100) >> 8
    Zero = (Flag & 0x040) >> 6

    if(Opcode == 1):
        print("Flag = Opecode")
        print("")

    if(TC == 1):
        print("Flag = TC")
        print("")

    if(RD == 1):
        print("Flag = RD")
        print("")

    if(Zero == 1):
        print("Flag = Zero")
        print("")

    NumConsultas = (DatosUDP[4] << 8) | DatosUDP[5]
    print("Numero de consultas = ", NumConsultas)
    print("")

    NumRegistrosRespuesta = (DatosUDP[6] << 8) | DatosUDP[7]
    print("Numero de registros de respuesta = ", NumRegistrosRespuesta)
    print("")

    NumRegistrosAutoridad = (DatosUDP[8] << 8) | DatosUDP[9]
    print("Numero de registros de autoridad = ", NumRegistrosAutoridad)
    print("")

    NumRegistrosAdicionales = (DatosUDP[10] << 8) | DatosUDP[11]
    print("Numero de registros adicionales = ", NumRegistrosAdicionales)
    print("")


# recive 10 packages
for i in range(20):
    # receive a package
    print("")
    print('============================================================')
    datos0=s.recvfrom(65535)
    print('Paquete nº',i)
##    print('Datos 0')
##    print(datos0)
    datos1=datos0[0]
##    print('Datos 1')
##    print(datos1)
    DatagramaIP=list(datos1)
##    print('Datagrama IP')
##    print(DatagramaIP)
    CabeceraIP=DatagramaIP[:20]
    print('Cabecera IP')
    print(CabeceraIP)
    print("")

    DatosIP= DatagramaIP[20:]
    print('Datos IP')
    print(DatosIP)
    print("")

    Version=CabeceraIP[0]>>4
    print('Version = ',Version)
    print("")

    HL=CabeceraIP[0] & 0x0F
    print('Longitud cabecera = ',HL , ' palabrasde 32 bits')
    print("")

    ToS=CabeceraIP[1]
    print('ToS = ',ToS)
    print("")

    LongitudTotal1=(CabeceraIP[2] << 8) | CabeceraIP[3]
    ##LongitudTotal1=(CabeceraIP[2] * 256) + CabeceraIP[3]      esto es una forma alternativa
    print('Longitud total = ',LongitudTotal1)
    print("")

    Identificador=(CabeceraIP[4] << 8) | CabeceraIP[5]
    print('Identificador = ', hex(Identificador))
    print("")

    Fragmentacion=(CabeceraIP[6] << 8) | CabeceraIP[7]
    print('Fragmentacion = ', bin(Fragmentacion))
    print("")

    DF=(Fragmentacion & 0b0100000000000000) !=0     ##esto es un booleano
    MF=(Fragmentacion & 0b0010000000000000) !=0
    Offset=Fragmentacion & 0b0001111111111111
    print('DF = ', DF)
    print("")

    print('MF = ', MF)
    print("")

    print('Offset = ', Offset)
    print("")

    print('Desplazamiento del fragmento = ', Offset*8)
    print("")

    TiempoDeVida = CabeceraIP[8]
    print('Tiempo de vida(TTL) = ', TiempoDeVida)
    print("")

    EsICMP=False
    EsUDP=False
    EsTCP=False
    Protocolo = CabeceraIP[9]
    if(Protocolo==1):
            EsICMP=True
            print("Protocolo = ICMP, ", Protocolo)
    elif(Protocolo == 17):
            EsUDP=True
            print("Protocolo = UDP, ", Protocolo)
    elif(Protocolo == 6):
            EsTCP=True
            print("Protocolo = TCP, ", Protocolo)
    print("")

    Checksum=(CabeceraIP[10]<<8) | CabeceraIP[11]
    print("Checksum IP = ", hex(Checksum))
    print("")

    print("Ip Origen = ", CabeceraIP[12], ".", CabeceraIP[13], ".", CabeceraIP[14], ".", CabeceraIP[15])
    print("")

    print("Ip Destino = ", CabeceraIP[16], ".", CabeceraIP[17], ".", CabeceraIP[18], ".", CabeceraIP[19])
    print("")

    if(EsICMP==True):
        ICMPFunc(DatosIP)
    elif(EsTCP==True):
        TCPFunc(DatosIP)
    elif(EsUDP==True):
        UDPFunc(DatosIP)




# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)



