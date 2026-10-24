# scoring.py — оцінювання переліку загроз для Варіанта 14 (СЕД кафедри)
import sys
from pathlib import Path

# Додаємо каталог з cvss.py у шлях пошуку модулів
sys.path.append(str(Path(__file__).resolve().parent.parent / "lab01_threat_model"))
from cvss import base_score

threats = {
    "T-01 (Витік JWT)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "T-02 (IDOR до чужих даних)": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T-03 (Витік у трасуванні помилки)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T-04 (Прямий доступ до файлів docs)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "T-05 (SQL Injection)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "T-06 (Витік лінка скидання пароля)": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "T-07 (Брутфорс пароля)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "T-08 (DDoS атака)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "T-09 (Відсутність аудиту)": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
    "T-10 (Завантаження веб-шелла)": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "T-11 (Невалідний JWT без перевірки)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "T-12 (Пряма модифікація у сховищі)": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
}


def get_risk_rank(score: float) -> str:
    if score >= 9.0:
        return "Критичний"
    if score >= 7.0:
        return "Високий"
    if score >= 4.0:
        return "Середній"
    return "Низький"


if __name__ == "__main__":
    print(f"{'ID загрози':<38} | {'Оцінка':<6} | {'Рівень':<10} | {'Вектор CVSS'}")
    print("-" * 90)
    for tid, vector in threats.items():
        score = base_score(vector)
        rank = get_risk_rank(score)
        print(f"{tid:<38} | {score:<6.1f} | {rank:<10} | {vector}")
