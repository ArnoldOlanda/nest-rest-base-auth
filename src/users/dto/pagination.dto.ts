import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsOptional, IsPositive, Min } from 'class-validator';

export class PaginationDto {
  @IsOptional()
  @IsPositive()
  @Type(() => Number)
  @ApiProperty({
    description: 'Number of items to return',
    type: 'number',
    default: 10,
  })
  limit?: number = 10;

  @IsOptional()
  @Min(0)
  @Type(() => Number)
  @ApiProperty({
    description: 'Number of items to skip',
    type: 'number',
    default: 0,
  })
  offset?: number = 0;
}
