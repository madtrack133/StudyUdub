from models import Student

def test_create_student(db):
    # directly use the ORM
    u = Student(UniStudentID="U123", FirstName="A", LastName="B", Email="a@b.com")
    u.set_password("Aa1!aaaa")
    db.session.add(u)
    db.session.commit()

    got = Student.query.filter_by(UniStudentID="U123").first()
    assert got is not None
    assert got.check_password("Aa1!aaaa")
