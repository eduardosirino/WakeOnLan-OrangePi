#!/bin/bash
# Script de instalacao Wake-on-LAN para Orange Pi
# Execute como root: sudo bash install.sh

set -e

echo "================================================"
echo "  Wake-on-LAN Web Interface - Instalador"
echo "================================================"
echo ""

# Verificar se esta rodando como root
if [ "$EUID" -ne 0 ]; then
    echo "Por favor, execute como root: sudo bash install.sh"
    exit 1
fi

# Diretorio de instalacao
INSTALL_DIR="/opt/wol-web"
SERVICE_NAME="wol-web"
USER_NAME="wol"

echo "[1/6] Atualizando sistema..."
apt-get update -qq

echo "[2/6] Instalando dependencias..."
apt-get install -y python3 python3-pip python3-venv

echo "[3/6] Criando usuario de servico..."
if ! id "$USER_NAME" &>/dev/null; then
    useradd -r -s /bin/false $USER_NAME
fi

echo "[4/6] Instalando aplicacao..."
mkdir -p $INSTALL_DIR
cp -r . $INSTALL_DIR/
cd $INSTALL_DIR

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate
pip install --quiet -r requirements.txt
deactivate

# Ajustar permissoes
chown -R $USER_NAME:$USER_NAME $INSTALL_DIR

echo "[5/6] Configurando servico systemd..."
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Wake-on-LAN Web Interface
After=network.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo "[6/6] Verificando instalacao..."
sleep 2
if systemctl is-active --quiet $SERVICE_NAME; then
    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "================================================"
    echo "  Instalacao concluida com sucesso!"
    echo "================================================"
    echo ""
    echo "Acesse: http://$IP:5000"
    echo ""
    echo "Login padrao:"
    echo "  Usuario: admin"
    echo "  Senha:   admin"
    echo ""
    echo "(Altere a senha na pagina de configuracao)"
    echo ""
    echo "Comandos uteis:"
    echo "  sudo systemctl status $SERVICE_NAME  # Ver status"
    echo "  sudo systemctl restart $SERVICE_NAME # Reiniciar"
    echo "  sudo systemctl stop $SERVICE_NAME    # Parar"
    echo "  sudo journalctl -u $SERVICE_NAME -f  # Ver logs"
    echo ""
else
    echo "ERRO: Servico nao iniciou corretamente."
    echo "Verifique os logs: sudo journalctl -u $SERVICE_NAME -f"
    exit 1
fi
