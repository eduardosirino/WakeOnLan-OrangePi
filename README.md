# Wake-on-LAN Web Interface

Interface web para ligar computadores remotamente via Wake-on-LAN, desenvolvida para Orange Pi Zero.

## Funcionalidades

- Interface web responsiva (funciona em desktop e mobile)
- Suporte a multiplos computadores
- CRUD completo via interface (adicionar, editar, remover)
- Status online/offline em tempo real via ping
- Autenticacao por senha
- Banco de dados SQLite (sem configuracao manual)

## Requisitos

- Orange Pi Zero (ou qualquer Linux com Python 3)
- Python 3.7+
- Acesso a rede local

## Instalacao Rapida (Orange Pi)

1. Clone o repositorio:
```bash
git clone https://github.com/seu-usuario/WakeOnLan-OrangePi.git
cd WakeOnLan-OrangePi
```

2. Execute o instalador:
```bash
sudo bash install.sh
```

3. Acesse: `http://<ip-do-orangepi>:5000`

**Senha padrao:** `admin` (altere na pagina de configuracao)

## Instalacao Manual

```bash
# Instalar dependencias
pip install -r requirements.txt

# Executar
python app.py
```

O servidor iniciara na porta 5000.

## Uso

1. Acesse a interface web e faca login
2. Va em **Configurar** para adicionar seus computadores:
   - Nome: identificacao do PC
   - MAC: endereco MAC da placa de rede (ex: `AA:BB:CC:DD:EE:FF`)
   - IP: endereco IP para verificar status (ex: `192.168.1.100`)
3. No **Dashboard**, clique em "Ligar" para enviar o pacote Wake-on-LAN

## Preparar o Computador para Wake-on-LAN

Para que o WoL funcione, o computador de destino precisa estar configurado:

### Windows
1. Abra o Gerenciador de Dispositivos
2. Va em Adaptadores de Rede > sua placa de rede
3. Em Propriedades > Gerenciamento de Energia, habilite "Permitir que este dispositivo ative o computador"
4. Em Propriedades > Avancado, habilite "Wake on Magic Packet"

### BIOS/UEFI
Habilite "Wake on LAN" ou "Power On by PCI-E" nas configuracoes da BIOS.

## Estrutura do Projeto

```
WakeOnLan-OrangePi/
├── app.py              # Servidor Flask
├── wol.db              # Banco de dados (criado automaticamente)
├── requirements.txt    # Dependencias Python
├── install.sh          # Script de instalacao
├── static/
│   ├── style.css       # Estilos
│   └── script.js       # JavaScript
└── templates/
    ├── login.html      # Pagina de login
    ├── index.html      # Dashboard
    └── config.html     # Configuracao
```

## Comandos do Servico (apos instalacao)

```bash
sudo systemctl status wol-web    # Ver status
sudo systemctl restart wol-web   # Reiniciar
sudo systemctl stop wol-web      # Parar
sudo journalctl -u wol-web -f    # Ver logs
```

## Licenca

MIT
