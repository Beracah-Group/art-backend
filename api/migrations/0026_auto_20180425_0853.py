# Generated by Django 2.0.1 on 2018-04-25 08:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0025_auto_20180418_1936'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='assetlog',
            options={'verbose_name': 'Asset Log'},
        ),
        migrations.AlterModelOptions(
            name='assetmake',
            options={'verbose_name': 'Asset Make'},
        ),
        migrations.AlterModelOptions(
            name='assetmodelnumber',
            options={'verbose_name': 'Asset Model Number'},
        ),
        migrations.AlterModelOptions(
            name='assettype',
            options={'verbose_name': 'Asset Type'},
        ),
        migrations.AlterField(
            model_name='assetmake',
            name='make_label',
            field=models.CharField(max_length=40, verbose_name='Asset Make'),
        ),
    ]