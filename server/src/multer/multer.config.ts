import { diskStorage } from 'multer';
import { extname } from 'path';
import { BadRequestException } from '@nestjs/common';

export const multerOptions = {
  storage: diskStorage({
    destination: './uploads/avatars',
    filename: (req, file, callback) => {
      const randomName = Array(32)
        .fill(null)
        .map(() => Math.round(Math.random() * 16).toString(16))
        .join('');
      callback(null, `${randomName}${extname(file.originalname)}`);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.match(/\/(jpg|jpeg|png|gif)$/)) {
      cb(null, true);
    } else {
      cb(new BadRequestException('Unsupported file type'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
};