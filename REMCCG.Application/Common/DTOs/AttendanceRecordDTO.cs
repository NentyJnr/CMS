﻿using REMCCG.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace REMCCG.Application.Common.DTOs
{
    public class AttendanceRecordDTO : BaseObjectDTO
    {
        public int ID { get; set; }
        public int AttendanceEventID { get; set; } 
        public ServiceAttendance AttendanceEvent { get; set; } 
        public int MemberID { get; set; }
        public Member Member { get; set; } 
        public bool AttendedMen { get; set; }
        public bool AttendedWomen { get; set; }
        public bool AttendedChildren { get; set; }
        public bool AttendedGuests { get; set; }
        public bool IsPastEvent { get; set; }
    }

    public class AttendanceRecordModel
    {
        public int ID { get; set; }
        public int AttendanceEventID { get; set; } // ID of the associated AttendanceEvent
        public ServiceAttendance AttendanceEvent { get; set; } // Navigation property for the associated AttendanceEvent
        public int MemberID { get; set; }
        public Member Member { get; set; } // Navigation property for the associated Member
        public bool AttendedMen { get; set; }
        public bool AttendedWomen { get; set; }
        public bool AttendedChildren { get; set; }
        public bool AttendedGuests { get; set; }
        public bool IsPastEvent { get; set; }
    }
}
