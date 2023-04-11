import { Body, Controller, Post, HttpCode, HttpStatus, UseGuards, Get, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from './auth.guard';
import { RolesGuard } from './roles/roles.guard';
import { Roles } from './roles/roles.decorator';
import { Role } from './roles/enums/role.enum';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  signIn(@Body() signInDto: Record<string, any>) {
    return this.authService.signIn(signInDto.username, signInDto.password);
  }

  @UseGuards(AuthGuard,RolesGuard)
  @Roles(Role.Admin)
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }
}