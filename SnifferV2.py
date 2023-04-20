import socket


def Dns(DatosUDP):
    print("============================================================")
    print("DNS")
    CabeceraDNS= DatosUDP[0:12]
    DatosDNS=DatosUDP[12:]

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




def checksum(datos):
    suma = sum(datos)         # Suma todos los elementos de una lista
    suma = suma//65536 + suma%65536    # Calcula suma con carry para 16 bits
    suma = 65535 - suma                  # Complemento a uno para 16 bits
    return suma

def BytesAWords(Lista8):
    L = len(Lista8)                    # Obtiene longitud de la lista
    if L%2 != 0:                       # Si longitud es impar
        Lista8.append(0)               #    añade un elemento nulo
    L = len(Lista8)                    # Recalcula longitud de la lista
    L16 = []                           # Inicializa Lista de words (vacía)
    for i in range(0,L,2):             # Recorre la lista de bytes de 2 en 2 bytes
        L16 = L16 + [(Lista8[i] << 8) | (Lista8[i+1])]  # Construye word y la añade a la lista
    return L16

def datagramaTCP(CabeceraIP,DatosIP):
    print("============================================================")
    print("Cabecera TCP")
    print("")
    print("")
    CabeceraTCP= DatosIP[:20]
    DatosTCP=DatosIP[20:]

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

    ChecksumTCP = (DatosIP[16]<<8) | DatosIP[17]
    print("Checksum segmento = ", hex(ChecksumTCP))
    print("")
    length = len(DatosIP)
    DatosA = CabeceraIP[12:] + [0] + [6] + [length >> 16 & 0xFFFF, length & 0xFFFF] + DatosIP

    DatosA[28] = 0
    DatosA[29] = 0
    DatosX = BytesAWords(DatosA)

    print("Comprobacion del checksum:", hex(checksum(DatosX))==hex(ChecksumTCP))#comprueba si el checksum es correcto

    Puntero = (DatosIP[18]<<8) | DatosIP[19]
    print("Puntero a datos urgentes = ", hex(Puntero))
    print("")



def datagramaUDP(CabeceraIP,DatosIP):
    print("============================================================")
    print("Cabecera UDP")
    print("")
    CabeceraUDP= DatosIP[0:8]
    DatosUDP= DatosIP[8:]
    PuertoOrigen = (CabeceraUDP[0]<<8) | CabeceraUDP[1]
    PuertoDestino = (CabeceraUDP[2]<<8) | CabeceraUDP[3]
    Longitud = (CabeceraUDP[4]<<8) | CabeceraUDP[5]
    ChecksumUDP = (CabeceraUDP[6]<<8) | CabeceraUDP[7]
    print("Puerto origen: ", PuertoOrigen)
    print("")

    print("Puerto Destino: ",PuertoDestino)
    print("")

    print("Longitud total de UDP: ",Longitud)
    print("")

    print("Checksum: ",hex(ChecksumUDP))
    print("")

    DatosB=CabeceraIP[12:] + [0] + [17] + CabeceraUDP[4:6] + CabeceraUDP + DatosUDP
    DatosB[18] = 0
    DatosB[19] = 0
    DatosW = BytesAWords(DatosB)
    print("Comprobacion del checksum:", hex(checksum(DatosW))==hex(ChecksumUDP))#comprueba si el checksum es correcto
    print("")
    if (PuertoOrigen==53)or(PuertoDestino==53):
        Dns(DatosUDP)
    print("")


def datagramaICMP(DatosIP):
    print("============================================================")
    print("Cabecera ICMP")
    print("")
    print("")

    Tipo = DatosIP[0]
    print('Tipo = ', Tipo)
    print("")

    if(Tipo == 0):
        print("El paquete ICMP es una contestacion de eco")
    elif(Tipo == 3):
        print("Error, destino inalcanzable")
    elif(Tipo == 8):
        print("El paquete ICMP es una peticion de eco")
    elif(Tipo == 11):
        print("Error, tiempo excedido")
    print("")

    Codigo = DatosIP[1]
    print("Codigo = ", Codigo)
    print("")

    ChecksumICMP=(DatosIP[2]<<8) | DatosIP[3]
    print("Checksum ICMP = ", hex(ChecksumICMP))
    print("")

def main():
    for i in range(10):
        mensaje=s.recvfrom(65565)

        DatagramaIP=list(mensaje[0])

        print("################ PAQUETE Nº", i, " #################")
        print(DatagramaIP)

        version = DatagramaIP[0] >> 4

        print('Version= ', version)

        if version==4:
            IHL=DatagramaIP[0] & 0x0F
            print('Longitud cabecera = ',IHL , ' palabrasde 32 bits')
            print("")

            CabeceraIP=DatagramaIP[:20]
            print('Cabecera IP')
            print(CabeceraIP)
            print("")

            DatosIP= DatagramaIP[20:]
            print('Datos IP')
            print(DatosIP)
            print("")

            ToS=CabeceraIP[1]
            print('ToS = ',ToS)
            print("")

            LongitudTotal1=(CabeceraIP[2] << 8) | CabeceraIP[3] #esto es una forma alternativa
            ##LongitudTotal1=(CabeceraIP[2] * 256) + CabeceraIP[3]
            print('Longitud total = ',LongitudTotal1)
            print("")

            Identificador=(CabeceraIP[4] << 8) | CabeceraIP[5]
            print('Identificador = ', hex(Identificador))
            print("")

            Fragmentacion=(CabeceraIP[6] << 8) | CabeceraIP[7]
            print('Fragmentacion = ', bin(Fragmentacion))
            print("")

            #DF y MF son booleanos
            DF=(Fragmentacion & 0b0100000000000000) !=0
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
            datosC=BytesAWords(CabeceraIP)

            print("Checksum IP = ", hex(Checksum))
            print("")
            print("Comprobacion del checksum:", hex(checksum(datosC))==hex(0))#comprueba si el checksum es correcto

            print("Ip Origen = ", CabeceraIP[12], ".", CabeceraIP[13], ".", CabeceraIP[14], ".", CabeceraIP[15])
            print("")

            print("Ip Destino = ", CabeceraIP[16], ".", CabeceraIP[17], ".", CabeceraIP[18], ".", CabeceraIP[19])
            print("")

            if(EsICMP==True):
                datagramaICMP(DatosIP)
            elif(EsTCP==True):
                datagramaTCP(CabeceraIP,DatosIP)
            elif(EsUDP==True):
                datagramaUDP(CabeceraIP, DatosIP)

            print("")
            print("")


HOST = socket.gethostbyname(socket.gethostname())
HOST='192.168.1.47'
# create a raw socket and bind it to the public interface
s =  socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package

main()
# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


