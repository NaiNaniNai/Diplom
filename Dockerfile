FROM python:3.10
WORKDIR /ministore_site

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install poetry
COPY ./pyproject.toml .
RUN poetry install
COPY . .
