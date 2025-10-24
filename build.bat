@echo off
echo 빌드 시작...
echo.

echo 1. 필요한 패키지 설치 중...
pip install -r requirements.txt
echo.

echo 2. EXE 파일 생성 중...
pyinstaller --onefile --windowed --name "aws_instance_control" aws_controller.py
echo.

echo 빌드 완료!
echo dist 폴더에서 aws_instance_control.exe 파일을 확인하세요.
echo.
pause
