# Generated by Django 5.0.6 on 2024-06-09 16:26

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AnalyzedTraffic',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('packet_rate', models.FloatField(verbose_name='Скорость передачи пакетов')),
                ('inter_arrival_time', models.FloatField(verbose_name='')),
                ('packet_size', models.FloatField(verbose_name='')),
                ('duration', models.FloatField(verbose_name='')),
                ('src_port', models.CharField(max_length=16, verbose_name='Порт источника')),
                ('dst_port', models.CharField(max_length=16, verbose_name='Порт назначения')),
                ('num_packets', models.FloatField(verbose_name='')),
                ('num_bytes', models.FloatField(verbose_name='')),
                ('protocol', models.CharField(max_length=64, verbose_name='Название протокола')),
                ('src_ip', models.CharField(max_length=32, verbose_name='IP источника')),
                ('dst_ip', models.CharField(max_length=32, verbose_name='IP назначения')),
                ('label', models.CharField(choices=[('Атака', 'Attack'), ('Нормальная активность', 'Normal activity')],
                                           max_length=128, verbose_name='Вывод')),
            ],
            options={
                'verbose_name': 'Анализируемый трафик',
                'verbose_name_plural': 'Анализируемые трафики',
            },
        ),
    ]