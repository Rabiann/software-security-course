"""Тести підсистеми розмежування доступу для Варіанта 14 (RBAC, D2, A1, A5)."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from accesscontrol.monitor import AnomalyDetector, AuditLog, Permission, ReferenceMonitor, subjects_with_access
from mypolicy import VariantPolicy, create_variant14_policy, objects_accessible_by


def test_variant14_population_counts():
    """Перевірка обов'язкових кількостей варіанта: 10 суб'єктів та 23 об'єкти."""
    policy, subjects, objects = create_variant14_policy()
    assert len(subjects) == 10
    assert len(objects) == 23


def test_role_hierarchy_inheritance():
    """Перевірка успадкування прав: admin -> manager -> user."""
    policy, subjects, objects = create_variant14_policy()
    mon = ReferenceMonitor(policy)

    # u1 має роль admin:
    # 1. Свої права (admin): повний доступ до doc19
    assert mon.check("u1", "doc19", Permission.ADMIN).allowed
    # 2. Успадковані від manager: WRITE до doc11
    assert mon.check("u1", "doc11", Permission.WRITE).allowed
    # 3. Успадковані від user: READ до doc1
    assert mon.check("u1", "doc1", Permission.READ).allowed

    # u3 має роль manager:
    # Має права manager та user, але НЕ має прав admin
    assert mon.check("u3", "doc11", Permission.WRITE).allowed
    assert mon.check("u3", "doc1", Permission.READ).allowed
    assert not mon.check("u3", "doc19", Permission.ADMIN).allowed

    # u6 має роль user:
    # Має тільки права user, старші ролі недоступні
    assert mon.check("u6", "doc1", Permission.READ).allowed
    assert not mon.check("u6", "doc11", Permission.WRITE).allowed
    assert not mon.check("u6", "doc19", Permission.ADMIN).allowed


def test_safe_default():
    """Принцип безпечних значень за замовчуванням (safe default)."""
    policy, subjects, objects = create_variant14_policy()
    mon = ReferenceMonitor(policy)

    # Невідомий користувач
    d1 = mon.check("unknown_user", "doc1", Permission.READ)
    assert not d1.allowed
    assert "safe default" in d1.reason

    # Відомий користувач просить право, яке не надане
    d2 = mon.check("u6", "doc1", Permission.DELETE)
    assert not d2.allowed
    assert "safe default" in d2.reason


def test_temporary_permission_rule_d2():
    """Додаткове правило D2: тимчасові права з терміном дії."""
    p = VariantPolicy()
    p.add_role("temp_role")
    p.assign_role("temp_user", "temp_role")

    now = time.time()
    # Чинне тимчасове право (дійсне ще 100 секунд)
    p.grant("temp_role", "doc_active", Permission.READ, valid_until=now + 100)
    # Прострочене право (термін сплив 10 секунд тому)
    p.grant("temp_role", "doc_expired", Permission.READ, valid_until=now - 10)

    mon = ReferenceMonitor(p)
    assert mon.check("temp_user", "doc_active", Permission.READ).allowed
    assert not mon.check("temp_user", "doc_expired", Permission.READ).allowed


def test_anomaly_a1_denial_burst():
    """Аномалія А1: сплеск відмов у доступі від одного суб'єкта."""
    policy, subjects, objects = create_variant14_policy()
    mon = ReferenceMonitor(policy)
    detector = AnomalyDetector()

    # Робимо 3 відмови для користувача u6
    mon.check("u6", "doc19", Permission.ADMIN)
    mon.check("u6", "doc19", Permission.WRITE)
    mon.check("u6", "doc19", Permission.DELETE)

    alerts = detector.scan(mon.audit)
    assert any("u6 exceeded 3 failures" in a for a in alerts)


def test_anomaly_a5_first_time_action():
    """Аномалія А5: використання прав, не задіяних раніше."""
    policy, subjects, objects = create_variant14_policy()
    mon = ReferenceMonitor(policy)
    detector = AnomalyDetector()

    # 1. u1 виконує READ (перша дія в системі, фіксується як початкова)
    mon.check("u1", "doc1", Permission.READ)
    assert detector.scan(mon.audit) == []

    # 2. u1 знову виконує READ (дія вже відома, алерту немає)
    mon.check("u1", "doc2", Permission.READ)
    assert detector.scan(mon.audit) == []

    # 3. u1 вперше виконує іншу дію — WRITE! (має спрацювати детектор А5)
    mon.check("u1", "doc11", Permission.WRITE)
    alerts = detector.scan(mon.audit)
    assert any("Subject u1 performs action WRITE first time" in a for a in alerts)

    # 4. u1 повторно виконує WRITE — нового алерту для WRITE не з'являється
    mon.check("u1", "doc12", Permission.WRITE)
    alerts2 = detector.scan(mon.audit)
    write_alerts = [a for a in alerts2 if "Subject u1 performs action WRITE first time" in a]
    assert len(write_alerts) == 1



def test_dual_queries_consistency():
    """Двоїсті запити: subjects_with_access та objects_accessible_by."""
    policy, subjects, objects = create_variant14_policy()

    # Хто має доступ до читання doc1: усі 10 користувачів (через роль user або її успадкування)
    readers_doc1 = subjects_with_access(policy, subjects, "doc1", Permission.READ)
    assert len(readers_doc1) == 10
    assert set(readers_doc1) == set(subjects)

    # До чого має доступ користувач u6 (роль user) на читання: doc1..doc10 + doc23 (11 документів)
    accessible_u6 = objects_accessible_by(policy, "u6", objects, Permission.READ)
    assert len(accessible_u6) == 11
    assert "doc1" in accessible_u6
    assert "doc23" in accessible_u6
    assert "doc11" not in accessible_u6

    # Узгодженість запитів
    for s in subjects:
        for o in objects[:5]:
            has_access_s = s in subjects_with_access(policy, subjects, o, Permission.READ)
            has_access_o = o in objects_accessible_by(policy, s, objects, Permission.READ)
            assert has_access_s == has_access_o
