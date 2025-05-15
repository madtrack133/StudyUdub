from models import (
    db, Student, Course, Assignment, Notes, Share
)

def test_create_student(db):
    # directly use the ORM
    u = Student(UniStudentID="U123", FirstName="A", LastName="B", Email="a@b.com")
    u.set_password("Aa1!aaaa")
    db.session.add(u)
    db.session.commit()

    got = Student.query.filter_by(UniStudentID="U123").first()
    assert got is not None
    assert got.check_password("Aa1!aaaa")

def test_create_course(db):
    # create a new course
    course = Course(
        UnitCode="TEST101",
        CourseName="Introduction to Testing",
        CreditPoints=6
    )
    db.session.add(course)
    db.session.commit()

    got = Course.query.filter_by(UnitCode="TEST101").first()
    assert got is not None
    assert got.CourseName == "Introduction to Testing"
    assert got.CreditPoints == 6
