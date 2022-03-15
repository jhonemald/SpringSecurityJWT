package org.ada.school.user.service;


import org.ada.school.user.controller.user.UserDto;
import org.ada.school.user.exception.UserNotFoundException;
import org.ada.school.user.repository.document.User;

import java.util.List;

public interface UserService
{
    User create( UserDto userDto );

    User findById( String id )
        throws UserNotFoundException;

    User findByEmail( String email )
        throws UserNotFoundException;

    List<User> all();

    boolean deleteById( String id );

    User update( UserDto userDto, String id );
}
