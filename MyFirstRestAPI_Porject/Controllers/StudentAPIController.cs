using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Stripe.Issuing;
using Stripe.TestHelpers.Issuing;
using StudentApi.DataSimulation;
using StudentApi.Models;
using System.Collections.Generic;
using System.Security.Claims;

namespace StudentApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/Students")]



    public class StudentsController : ControllerBase
    {
        private readonly IAuthorizationService _authorizationService;
        public StudentsController(IAuthorizationService authorizationService) =>
            _authorizationService = authorizationService;


        [Authorize(Roles = "Admin")]
        [HttpGet("All", Name = "GetAllStudents")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public ActionResult<IEnumerable<Student>> GetAllStudents()
        {

            if (StudentDataSimulation.StudentsList.Count == 0)
            {
                return NotFound("No Students Found!");
            }
            return Ok(StudentDataSimulation.StudentsList);
        }

        [AllowAnonymous]
        [HttpGet("Passed", Name = "GetPassedStudents")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public ActionResult<IEnumerable<Student>> GetPassedStudents()

        {
            var passedStudents = StudentDataSimulation.StudentsList.Where(student => student.Grade >= 50).ToList();

            if (passedStudents.Count == 0)
                return NotFound("No Students Passed");

            return Ok(passedStudents);
        }

        [AllowAnonymous]
        [HttpGet("AverageGrade", Name = "GetAverageGrade")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<double> GetAverageGrade()
        {
            if (StudentDataSimulation.StudentsList.Count == 0)
                return NotFound("No students found.");

            var averageGrade = StudentDataSimulation.StudentsList.Average(student => student.Grade);
            return Ok(averageGrade);
        }


        [HttpGet("{id}", Name = "GetStudentById")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<Student>> GetStudentById(int id)
        {
            if (id < 1)
                return BadRequest($"Not accepted ID {id}");

            var student = StudentDataSimulation.StudentsList
                                .FirstOrDefault(s => s.Id == id);

            if (student == null)
                return NotFound($"Student with ID {id} not found.");

            var authResult = await _authorizationService
                    .AuthorizeAsync(User, id, "StudentOwnerOrAdmin");

            if (!authResult.Succeeded)
                return Forbid();

            return Ok(student);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost(Name = "AddStudent")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public ActionResult<Student> AddStudent(Student newStudent)
        {
            if (newStudent == null || string.IsNullOrEmpty(newStudent.Name) || newStudent.Age < 0 || newStudent.Grade < 0)
            {
                return BadRequest("Invalid student data.");
            }

            newStudent.Id = StudentDataSimulation.StudentsList.Count > 0 ? StudentDataSimulation.StudentsList.Max(s => s.Id) + 1 : 1;
            StudentDataSimulation.StudentsList.Add(newStudent);

            return CreatedAtRoute("GetStudentById", new { id = newStudent.Id }, newStudent);

        }

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}", Name = "DeleteStudent")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public ActionResult DeleteStudent(int id)
        {
            if (id < 1)
            {
                return BadRequest($"Not accepted ID {id}");
            }

            var student = StudentDataSimulation.StudentsList.FirstOrDefault(s => s.Id == id);
            if (student == null)
            {
                return NotFound($"Student with ID {id} not found.");
            }

            StudentDataSimulation.StudentsList.Remove(student);
            return Ok($"Student with ID {id} has been deleted.");
        }
        [HttpPut("{id}", Name = "UpdateStudent")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        [ProducesResponseType(403)]
        public async Task<ActionResult<Student>> UpdateStudent(int id, Student updatedStudent)
        {
            if (id < 1 || updatedStudent == null ||
                string.IsNullOrEmpty(updatedStudent.Name) ||
                updatedStudent.Age < 0 ||
                updatedStudent.Grade < 0)
                return BadRequest("Invalid student data.");

            var student = StudentDataSimulation.StudentsList
                                .FirstOrDefault(s => s.Id == id);

            if (student == null)
                return NotFound($"Student with ID {id} not found.");

            // 🔐 AUTH CHECK (مهم قبل التعديل)
            var authResult = await _authorizationService.AuthorizeAsync(
                User,
                id,
                "StudentOwnerOrAdmin"
            );

            if (!authResult.Succeeded)
                return Forbid();

            // ✏️ التعديل بعد التأكد من الصلاحية
            student.Name = updatedStudent.Name;
            student.Age = updatedStudent.Age;
            student.Grade = updatedStudent.Grade;

            return Ok(student);
        }


    }
}
