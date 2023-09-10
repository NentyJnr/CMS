﻿using REMCCG.Application.Common.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace REMCCG.Application.Interfaces.Members
{
    public interface IMemberService:ICRUD<MemberDTO, MemberModel>
    {
    }
}
