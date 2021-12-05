FROM skysider/pwndocker:latest

RUN curl -sL https://deb.nodesource.com/setup_16.x | bash - && apt -y install nodejs

RUN pip install jupyterlab && pip install --upgrade jupyterlab-vim

COPY jupyterlab /etc/service/jupyterlab
