FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

COPY . .

ENV ERP_SECRET_KEY=change-me
ENV ERP_DATABASE_URL=sqlite:////data/erp.db
ENV ERP_HOST=0.0.0.0
ENV ERP_PORT=8000

VOLUME ["/data"]

EXPOSE 8000

CMD ["python", "app.py"]
