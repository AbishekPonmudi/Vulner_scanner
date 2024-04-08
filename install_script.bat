@echo off
echo Installing/upgrading pip...
python -m pip install --upgrade pip

echo Installing tqdm...
python -m pip install tqdm

echo Downloading Python installer...
curl -O https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe

echo Installing Python...
python-x.y.z-amd64.exe

echo Displaying Python version...
python --version
python3 --version

echo Downloading Nmap installer...
curl -O https://nmap.org/dist/nmap-7.92-setup.exe

echo Installing Nmap...
nmap-7.92-setup.exe

echo Installing required Python packages...
pip install python-nmap tqdm colorama

echo Installation completed.
pause
