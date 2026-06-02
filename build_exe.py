import subprocess, sys, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
print("Installing dependencies...")
subprocess.run([sys.executable,"-m","pip","install","pyinstaller","pymem"],check=True)
print("Building exe...")
subprocess.run([sys.executable,"-m","PyInstaller",
    "--onefile","--noconsole","--name","WartalesTrainer",
    "--hidden-import","pymem",
    "--hidden-import","pymem.pattern",
    "--hidden-import","pymem.ressources.structure",
    "wartales_trainer.py"],check=True)
print("\nDone! EXE -> dist\\WartalesTrainer.exe")
input("Press Enter...")
