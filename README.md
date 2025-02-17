# **Nexora**

**Nexora** — это универсальный скрипт для автоматической оптимизации VPS-серверов под высокую производительность. Скрипт настраивает систему, устанавливает 3x-ui с автонастройкой TLS-сертификата, усиливает безопасность, добавляет мониторинг и отправляет уведомления через Telegram.

---

## **Особенности**
- **Обновление системы**: Установка последних пакетов и удаление устаревших.
- **Оптимизация сети**: Включение BBR, настройка TCP-параметров.
- **Управление памятью**: Автоматическое создание Swap или настройка Zram.
- **3x-ui с автонастройкой**: Установка 3x-ui и генерация TLS-сертификата через Let's Encrypt.
- **Безопасность**: Настройка UFW, Fail2Ban и защита SSH.
- **Мониторинг**: Установка инструментов (htop, iftop, net-tools).
- **Автоматические обновления**: Настройка unattended-upgrades.
- **Резервное копирование**: Ежедневное резервное копирование важных файлов.
- **Уведомления через Telegram**: Отправка уведомлений о завершении работы скрипта.
- **Проверка сервисов**: Проверка статуса ключевых служб после выполнения.

---

## **Требования**
- ОС: Ubuntu 20.04/22.04 (рекомендуется).
- Минимальные требования: 1 ГБ RAM, 1 CPU.
- Доменное имя (для генерации TLS-сертификата).
- Telegram Bot Token и Chat ID (для уведомлений).

---

## **Установка**
1. Подключитесь к вашему серверу через SSH:
   ```bash
   ssh root@your-server-ip
   ```

2. Скачайте скрипт:
   ```bash
   wget https://raw.githubusercontent.com/IgorMelenchuk/Nexora/main/Nexora.sh
   ```

3. Сделайте скрипт исполняемым:
   ```bash
   chmod +x Nexora.sh
   ```

4. Запустите скрипт:
   ```bash
   sudo ./Nexora.sh
   ```

---

## **Использование**
При запуске скрипта вам будет предложено ввести следующие данные:
1. **Доменное имя**: Например, `example.com`.
2. **Email для сертификата**: Например, `admin@example.com`.
3. **Telegram Bot Token**: Получите его через [@BotFather](https://t.me/BotFather).
4. **Chat ID**: Найдите его через [@userinfobot](https://t.me/userinfobot).

Скрипт автоматически выполнит все шаги и выведет логи в файл `/var/log/Nexora.log`.

---

## **Что делает скрипт?**
1. Обновляет систему.
2. Оптимизирует сетевые параметры (BBR, TCP).
3. Создает Swap или настраивает Zram.
4. Устанавливает 3x-ui с автонастройкой VLESS и TLS.
5. Отключает ненужные службы.
6. Усиливает безопасность (UFW, Fail2Ban, SSH).
7. Устанавливает инструменты мониторинга.
8. Настройка автоматических обновлений.
9. Создает резервные копии.
10. Отправляет уведомления через Telegram.

---

## **Дополнительные примечания**
- **DNS-записи**: Убедитесь, что доменное имя указывает на IP-адрес вашего сервера.
- **Логи**: Все действия записываются в `/var/log/Nexora.log`.
- **3x-ui**: После установки доступ к панели осуществляется по адресу `https://<your-server-ip>:2053`.
- **Telegram**: Если не хотите получать уведомления, просто пропустите ввод Bot Token и Chat ID.



## **Поддержка**
Если у вас возникли вопросы или проблемы:
- Откройте issue в репозитории.
- Свяжитесь с автором через Telegram: @fuegodentro

---

## **Благодарности**
- [3x-ui](https://github.com/MHSanaei/3x-ui) за отличную панель управления.
- [@BotFather](https://t.me/BotFather) за простое создание Telegram-бота.
- Сообщество Linux за бесценные советы по оптимизации.
