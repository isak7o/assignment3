FROM python:3.9

WORKDIR /app
#copy from current dir to working dir
COPY . /app

RUN pip install -r requirements.txt

#Make port 5000 available to other clients, outside the containers
EXPOSE 5000

CMD ["python", "app.py"]