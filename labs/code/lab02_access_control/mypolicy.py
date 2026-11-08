from accesscontrol.monitor import Decision, Permission, Policy
from time import time

class PermProps:
    def __init__(self, permission: Permission, until: float | None):
        self.permission: Permission = permission
        self.until: float | None = until

class RoleProps:
    def __init__(self):
        self.subroles: set[str] = set()
        self.permissions: dict[str, PermProps] = dict()

class VariantPolicy(Policy):
    def __init__(self) -> None:
        self.users: dict[str, str] = {}
        self.roles: dict[str, RoleProps] = {}
        # TODO(варіант): додати структури під свою модель:
    
    def add_role(self, role: str):
        if self.roles.get(role):
            raise Exception('Role already exists')

        self.roles[role] = RoleProps()

    def assign_role(self, user: str, role: str):
        if not self.roles.get(role):
            raise Exception('Role does not exists')

        self.users[user] = role

    def add_role_hierarchy(self, parent_role: str, child_role: str):
        if not self.roles.get(parent_role):
            raise Exception('Role does not exists')

        self.roles[parent_role].subroles.add(child_role)


    def grant(self, role: str, obj: str, perm: Permission, valid_until: float | None = None) -> None:
        if not self.roles.get(role):
            raise Exception('Role does not exists')

        self.roles[role].permissions[obj] = PermProps(perm, valid_until)


    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        # TODO(варіант): обчислити ефективні права згідно з моделлю
        total_permission = Permission.NONE
        subject_role = self.users.get(subject)
        if not subject_role:
            return Decision(False, "явного дозволу немає (safe default)")
        queue = [subject_role]
        visited = set()

        while queue:
            o = queue.pop(0)
            if o not in visited and o in self.roles:
                visited.add(o)
                effective = self.roles[o].permissions.get(obj)
                if effective is not None:
                    is_time_ok = effective.until is None or effective.until >= time()
                    if is_time_ok:
                        total_permission |= effective.permission
                        if (action & total_permission) == action:
                            return Decision(True, "надано")

                for sp in self.roles[o].subroles:
                    queue.append(sp)

        return Decision(False, "явного дозволу немає (safe default)")


def objects_accessible_by(policy: Policy, subject: str, objects: list[str], action: Permission) -> list[str]:
    """Двоїстий запит: до яких об'єктів суб'єкт має вказане право."""
    return [o for o in objects if policy.evaluate(subject, o, action).allowed]


def create_variant14_policy() -> tuple[VariantPolicy, list[str], list[str]]:
    """Наповнення політики для Варіанта 14 (10 суб'єктів, 23 об'єкти, RBAC + D2)."""
    p = VariantPolicy()

    # Створюємо ролі з ієрархією: admin -> manager -> user
    for r in ["admin", "manager", "user"]:
        p.add_role(r)

    p.add_role_hierarchy("admin", "manager")
    p.add_role_hierarchy("manager", "user")

    # 10 суб'єктів та 23 об'єкти
    subjects = [f"u{i}" for i in range(1, 11)]
    objects = [f"doc{i}" for i in range(1, 24)]

    # Призначення ролей:
    # u1, u2 -> admin
    # u3, u4, u5 -> manager
    # u6, u7, u8, u9, u10 -> user
    for s in subjects[:2]:
        p.assign_role(s, "admin")
    for s in subjects[2:5]:
        p.assign_role(s, "manager")
    for s in subjects[5:]:
        p.assign_role(s, "user")

    # doc1..doc10: загальні документи (права у ролі user)
    for o in objects[:10]:
        p.grant("user", o, Permission.READ)

    # doc11..doc18: управлінські документи (права у ролі manager)
    for o in objects[10:18]:
        p.grant("manager", o, Permission.READ | Permission.WRITE)

    # doc19..doc22: критичні документи (права у ролі admin)
    for o in objects[18:22]:
        p.grant("admin", o, Permission.ADMIN)

    # doc23: тимчасовий документ (додаткове правило D2: діє 1 годину)
    p.grant("user", "doc23", Permission.READ, valid_until=time() + 3600)

    return p, subjects, objects


if __name__ == "__main__":
    from accesscontrol.monitor import ReferenceMonitor, AnomalyDetector, subjects_with_access

    print("=" * 80)
    print("ДЕМОНСТРАЦІЯ РОБОТИ ПІДСИСТЕМИ РОЗМЕЖУВАННЯ ДОСТУПУ (ВАРІАНТ 14)")
    print("=" * 80)

    policy, subjects, objects = create_variant14_policy()
    mon = ReferenceMonitor(policy)

    test_cases = [
        ("u1", "doc19", Permission.ADMIN, "Власні права ролі admin"),
        ("u1", "doc11", Permission.WRITE, "Успадковано за ієрархією від manager"),
        ("u1", "doc1", Permission.READ, "Успадковано за ієрархією від user"),
        ("u3", "doc11", Permission.WRITE, "Власні права ролі manager"),
        ("u3", "doc1", Permission.READ, "Успадковано від user"),
        ("u3", "doc19", Permission.ADMIN, "Відмова: manager не має доступу до admin"),
        ("u6", "doc1", Permission.READ, "Власні права базової ролі user"),
        ("u6", "doc11", Permission.WRITE, "Відмова: user не має прав ролі manager"),
        ("u6", "doc23", Permission.READ, "Правило D2: термін дії ще не сплив"),
        ("u6", "doc23", Permission.READ, "Правило D2: перевірка після закінчення терміну дії"),
        ("unknown", "doc1", Permission.READ, "Відмова: суб'єкт без ролі (safe default)"),
        ("u6", "doc1", Permission.DELETE, "Відмова: операція не надана жодній ролі (safe default)"),
    ]

    print("\n1. ТАБЛИЦЯ ОЦІНЮВАННЯ ЗАПИТІВ (EVALUATE):")
    print(f"{'№':<3} {'Суб\'єкт':<9} {'Об\'єкт':<8} {'Дія':<8} {'Результат':<15} {'Причина / Обґрунтування'}")
    print("-" * 80)
    for i, (s, o, act, comment) in enumerate(test_cases, 1):
        if i == 10:
            # Моделюємо завершення терміну дії правила D2 для рядка 10
            policy.roles["user"].permissions["doc23"].until = time() - 10
            dec = mon.check(s, o, act)
            # Відновлюємо чинність для подальших двоїстих запитів
            policy.roles["user"].permissions["doc23"].until = time() + 3600
        else:
            dec = mon.check(s, o, act)

        res_str = "ДОЗВОЛЕНО" if dec.allowed else "ЗАБОРОНЕНО"
        print(f"{i:<3} {s:<9} {o:<8} {act.name:<8} {res_str:<15} {dec.reason} ({comment})")

    print("\n2. ДВОЇСТІ ЗАПИТИ:")
    readers_doc1 = subjects_with_access(policy, subjects, "doc1", Permission.READ)
    print(f"* Хто може читати doc1: {readers_doc1} (всього: {len(readers_doc1)})")

    writers_doc11 = subjects_with_access(policy, subjects, "doc11", Permission.WRITE)
    print(f"* Хто може писати в doc11: {writers_doc11} (всього: {len(writers_doc11)})")

    u6_docs = objects_accessible_by(policy, "u6", objects, Permission.READ)
    print(f"* До яких об'єктів u6 має доступ на READ: {u6_docs} (всього: {len(u6_docs)})")

    print("\n3. РЕЄСТРАЦІЙНИЙ ЖУРНАЛ (AUDIT LOG DUMP):")
    print(mon.audit.dump())

    print("\n4. ДЕТЕКЦІЯ АНОМАЛІЙ (A1 ТА A5):")
    # Додаємо аномалії для демонстрації:
    # A1: 3 відмови поспіль для u6
    mon.check("u6", "doc19", Permission.ADMIN)
    mon.check("u6", "doc19", Permission.ADMIN)
    mon.check("u6", "doc19", Permission.ADMIN)

    detector = AnomalyDetector()
    alerts = detector.scan(mon.audit)
    print("Виявлені аномалії:")
    for alert in alerts:
        print(f"  [ALERT] {alert}")