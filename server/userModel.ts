import * as mongoose from 'mongoose';

interface IUser extends mongoose.Document {
    username: string,
    email: string,
    password: string,
    role: string,
    activated: boolean,
    memberSince: number
}

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true },
    activated: { type: Boolean, required: true },
    memberSince: { type: Number, required: true }
});

export const UserModel = mongoose.model<IUser>('User', UserSchema);
