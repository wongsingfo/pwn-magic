FROM skysider/pwndocker:latest

RUN pip install jupyterlab 

RUN curl -sL https://deb.nodesource.com/setup_16.x | bash - && apt -y install nodejs

RUN pip install --upgrade jupyterlab-vim
