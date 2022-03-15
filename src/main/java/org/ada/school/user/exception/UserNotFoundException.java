package org.ada.school.user.exception;

import org.ada.school.user.error.ErrorCodeEnum;
import org.ada.school.user.error.InternalServerErrorException;
import org.springframework.http.HttpStatus;

public class UserNotFoundException
    extends InternalServerErrorException
{
    public UserNotFoundException()
    {
        super( new ServerErrorResponseDto( "User not found", ErrorCodeEnum.USER_NOT_FOUND, HttpStatus.NOT_FOUND ),
               HttpStatus.NOT_FOUND );
    }
}
