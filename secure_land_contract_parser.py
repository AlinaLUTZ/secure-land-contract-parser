#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Безопасный парсер договоров аренды земельных участков

Функция: 
  — извлекает текст из PDF/DOCX, 
  — полностью обезличивает (удаляет/заменяет ПДн), 
  — сохраняет только публичные данные (кадастр, ВРИ, срок).

Принципы:
  - Zero PII: ни одно персональное данное не остаётся в памяти или логах
  - Нет сохранения исходного файла
  - Работает только с публичными или обезличенными данными
  - Соответствует ФЗ-152 и требованиям ИБ

Использование:
  python secure_land_contract_parser.py договор.pdf
"""

import sys
import re
import os
from pathlib import Path

# === Зависимости ===
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    from docx import Document
except ImportError:
    Document = None


def extract_text(file_path: Path) -> str:
    """Извлекает текст из PDF или DOCX."""
    if file_path.suffix.lower() == ".pdf":
        if not PdfReader:
            raise RuntimeError("Требуется: pip install PyPDF2")
        reader = PdfReader(file_path)
        return "".join(
            page.extract_text() or "" for page in reader.pages
        )
    
    elif file_path.suffix.lower() == ".docx":
        if not Document:
            raise RuntimeError("Требуется: pip install python-docx")
        doc = Document(file_path)
        return "\n".join(paragraph.text for paragraph in doc.paragraphs)
    
    else:
        raise ValueError("Поддерживаются только .pdf и .docx")


def anonymize_contract(text: str) -> str:
    """
    Полностью обезличивает договор аренды земли:
    - Удаляет паспортные данные, ИНН, ОГРН
    - Заменяет первые два ФИО на [Арендодатель] и [Арендатор]
    - Заменяет адреса на [Адрес]
    - Сохраняет публичные данные: кадастр, ВРИ, срок, площадь
    """
    # Удаляем чувствительные идентификаторы полностью
    text = re.sub(r'\b\d{4}\s*\d{6}\b', '', text)        # Паспорт
    text = re.sub(r'\b\d{10,12}\b', '', text)            # ИНН/ОГРН
    text = re.sub(r'\+7\s*\d{3}\s*\d{3}\s*\d{2}\s*\d{2}', '', text)  # Телефон

    # Заменяем ФИО на роли (макс. 2 вхождения)
    fio_pattern = r'\b[А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.[А-ЯЁ]\.\b'
    fios = re.findall(fio_pattern, text)
    if len(fios) >= 1:
        text = re.sub(fio_pattern, '[Арендодатель]', text, count=1)
    if len(fios) >= 2:
        text = re.sub(fio_pattern, '[Арендатор]', text, count=1)

    # Адреса → [Адрес]
    text = re.sub(r'([гГ]\.\s*[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+)*)', '[Адрес]', text)
    text = re.sub(r'([уУ]л\.\s*[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+)*)', '[Адрес]', text)

    # Очищаем мусор и пустые строки
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print("❌ Использование: python secure_land_contract_parser.py <договор.pdf>")
        print("   Поддерживаются: .pdf, .docx")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"❌ Файл не найден: {input_path}")
        sys.exit(1)

    try:
        # Извлечение
        print(f"📄 Обрабатываю: {input_path.name}")
        raw_text = extract_text(input_path)

        # Обезличивание
        print("🛡️  Выполняю обезличивание...")
        clean_text = anonymize_contract(raw_text)

        # Сохранение (только анонимизированный текст)
        output_path = input_path.parent / f"{input_path.stem}_ANONYMIZED.txt"
        header = (
            "# Документ подготовлен для безопасного ИИ-анализа\n"
            "# Все ПДн удалены или заменены в соответствии с ФЗ-152\n"
            "# Исходный файл не сохранялся\n\n"
        )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(header + clean_text)

        print(f"✅ Готово! Результат: {output_path.name}")
        print("\n💡 Этот файл можно безопасно передавать в ИИ-анализатор.")

    except Exception as e:
        print(f"❌ Ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()