# Flask OWASP Project


## Requirements
- Python 3.x
- Flask

To run it:

python run.py

To run the Docker:
- docker build -t flask_app .
- docker run -p 5000:5000 flask_app

To run in that env:
python -m venv venv 
.\venv\Scripts\Activate 


#Başa eklenen yıldız yeni farkedilen olay, sona eklenmesi kritiklik #*a**
Yapılacaklar:
#register -> "123" passw
#rate limiting (register) + application genel(nginx) + login **
#upload_assignment -> file size **
#Vulnerability kalan 2? 8-9? ***
#*Captcha keyi ve //her runda yeni oluşan keyler. -> doğru şekilde saklanmalı ama nasıl**

Yapılan:
#@annatotation ile sırayla hatalar konuldu. IDOR engellendi.
#captcha reCaptcha v3 -> register ve login'e koydum.
#Registerda hata mesajını değiştirdim -> fazla bilgi veriyordu.
