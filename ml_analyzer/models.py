from django.db import models

from ml_analyzer.choices import LABEL


class AnalyzedTraffic(models.Model):
    """Model of analyzed network traffic"""

    packet_rate = models.FloatField(verbose_name="Скорость передачи пакетов")
    inter_arrival_time = models.FloatField(verbose_name="")
    packet_size = models.FloatField(verbose_name="")
    duration = models.FloatField(verbose_name="")
    src_port = models.CharField(max_length=16, verbose_name="Порт источника")
    dst_port = models.CharField(max_length=16, verbose_name="Порт назначения")
    num_packets = models.FloatField(verbose_name="")
    num_bytes = models.FloatField(verbose_name="")
    protocol = models.CharField(max_length=64, verbose_name="Название протокола")
    src_ip = models.CharField(max_length=32, verbose_name="IP источника")
    dst_ip = models.CharField(max_length=32, verbose_name="IP назначения")
    label = models.CharField(max_length=128, choices=LABEL, verbose_name="Вывод")

    class Meta:
        verbose_name = "Анализируемый трафик"
        verbose_name_plural = "Анализируемые трафики"

    def __str__(self):
        return f"{self.src_ip} - {self.label}"
